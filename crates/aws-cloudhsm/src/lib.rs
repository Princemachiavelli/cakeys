//! The AWS `CloudHSM` provider for Client SDK 5's `libcloudhsm_pkcs11.so` (`docs/CLOUD_HSM.md`).
//! The behavior that needs no code is data in the `aws-cloudhsm` profiles: a public key is always
//! private, the module lists AES key wraps but refuses them, and raw ECDH needs a client option.
//! The behavior that needs code is Ed25519. A non-FIPS cluster makes Ed25519 keys and signs with
//! them, but not through the standard mechanisms \[run\]:
//!
//! - The module lists no `CKM_EC_EDWARDS_KEY_PAIR_GEN`. It generates an Ed25519 key with
//!   `CKM_EC_KEY_PAIR_GEN` when `CKA_EC_PARAMS` holds the Ed25519 OID.
//! - The key's `CKA_KEY_TYPE` reads `CKK_EC`, and its `CKA_EC_POINT` holds the whole
//!   `SubjectPublicKeyInfo`.
//! - The module lists no `CKM_EDDSA`. It signs pure Ed25519 with the vendor mechanism
//!   `CKM_CLOUDHSM_EDDSA` (`0x80001057`), which takes no parameters, and the signature verifies
//!   as RFC 8032 Ed25519 on the host.
//!
//! cakeys relies on the stand-ins only where the profile's `add` row says that they work.
//! `caprobe` measures what [`Provider::stand_in`] covers. A FIPS cluster refuses the generation
//! ("Ed25519 key generation not available"), so its profile records no stand-in.

use cakeys_core::config::ModuleInfo;
use cakeys_pkcs11::Provider;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::KeyType;
use std::borrow::Cow;

/// `CKM_CLOUDHSM_EDDSA`: pure `EdDSA` with no parameters (`CKM_VENDOR_DEFINED | 0x1057`).
pub const CKM_CLOUDHSM_EDDSA: u64 = 0x8000_1057;

/// `CKA_EC_PARAMS` of an Ed25519 key: the OID 1.3.101.112 (RFC 8410).
const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// The bytes that precede the 32-byte point in an Ed25519 `SubjectPublicKeyInfo` (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The AWS `CloudHSM` provider (see the crate's documentation).
pub struct AwsCloudHsm;

/// Returns the point of an Ed25519 key whose `CKA_EC_POINT` is its whole SPKI, and returns any
/// other value unchanged.
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
        module.manufacturer == "CloudHSM"
    }

    /// An Ed25519 key's `CKA_EC_POINT` is its whole SPKI, so the point is the part that follows
    /// the prefix.
    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(ed25519_point(raw))
    }

    /// An Ed25519 key's `CKA_KEY_TYPE` reads `CKK_EC`, so the Ed25519 OID in `CKA_EC_PARAMS`
    /// marks the key as Edwards.
    fn key_type(&self, reported: KeyType, ec_params: Option<&[u8]>) -> KeyType {
        match (reported, ec_params) {
            (KeyType::EC, Some(p)) if p == ED25519_OID => KeyType::EC_EDWARDS,
            _ => reported,
        }
    }

    /// Ed25519 generation runs as `CKM_EC_KEY_PAIR_GEN` (the template's `CKA_EC_PARAMS` names
    /// the curve), and pure `EdDSA` runs as `CKM_CLOUDHSM_EDDSA`. Ed25519ctx, Ed25519ph and Ed448
    /// carry parameters, and the vendor mechanism takes no parameters, so they have no stand-in.
    fn stand_in(&self, m: &Mechanism) -> Option<Mechanism<'static>> {
        match m {
            Mechanism::EccEdwardsKeyPairGen => Some(Mechanism::EccKeyPairGen),
            // Without `CK_EDDSA_PARAMS`, the mechanism is pure EdDSA (`Pure`, or `Ed25519`
            // without a context).
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

    /// The provider in the form in which cakeys holds it (`dyn Provider`), so that the tests use
    /// the repaired reads as cakeys does.
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
        // `token::module_info` removes the padding before a provider is asked (review 2026-11-23
        // B-26), so the name is compared exactly.
        assert!(AwsCloudHsm.matches(&module("CloudHSM")));
        assert!(!AwsCloudHsm.matches(&module("CloudHSM2")));
        assert!(!AwsCloudHsm.matches(&module("SoftHSM")));
    }

    /// The point is taken from the SPKI that `CloudHSM` puts in `CKA_EC_POINT` \[run\], and any
    /// other value is kept.
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
        // The mechanisms that the probe measures, which are derived from the stand-ins above.
        assert_eq!(P.stand_ins(), [MechanismType::ECC_EDWARDS_KEY_PAIR_GEN, MechanismType::EDDSA]);
    }
}
