//! CA-ID computation: SRI rendering, spec digest, SPKI normalisation, commitment label.

use crate::config::{ObjectCfg, SpecCfg};
use crate::error::{KmError, Result};
use base64::Engine;
use p256::pkcs8::der::{asn1::OctetStringRef, Decode, Encode};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};

/// `sha256-<base64>`: drops straight into a Nix `outputHash`, but nothing depends on it.
pub fn sri(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes))
    )
}

/// Hash of the canonical JSON of (object type, policy attributes). Sorted keys via BTreeMap.
pub fn spec_digest(object: &ObjectCfg, spec: &SpecCfg) -> String {
    let canonical = serde_json::json!({
        "v": 1,
        "type": object,
        "attributes": spec.attributes,
    });
    sri(canonical.to_string().as_bytes())
}

/// Domain-separation label for secret-key commitments. The intrinsic type is mixed in so
/// the same bytes held as two key types never share an ID.
pub fn commitment_label(object: &ObjectCfg) -> Vec<u8> {
    format!(
        "key-management/v1/commitment/{}/{}",
        object.key_type,
        object.value_len.unwrap_or(0) * 8
    )
    .into_bytes()
}

/// Canonical DER SPKI from any SPKI encoding (`CKA_PUBLIC_KEY_INFO`, a certificate):
/// decode as P-256 or RSA and re-encode, so provider encoding quirks never change the hash.
pub fn spki_canonical(spki: &[u8]) -> Result<Vec<u8>> {
    if let Ok(key) = p256::PublicKey::from_public_key_der(spki) {
        return encode(&key);
    }
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("SPKI is neither P-256 nor RSA: {e}")))?;
    Ok(key
        .to_public_key_der()
        .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?
        .as_bytes()
        .to_vec())
}

/// Canonical DER SPKI from `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` (big-endian).
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::new(
        rsa::BoxedUint::from_be_slice_vartime(modulus),
        rsa::BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|e| KmError::Conflict(format!("invalid RSA public key: {e}")))?;
    Ok(key
        .to_public_key_der()
        .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?
        .as_bytes()
        .to_vec())
}

/// Canonical DER SPKI of a certificate's subject key: links a certificate to its key object.
pub fn cert_spki(cert: &[u8]) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert)
        .map_err(|e| KmError::Conflict(format!("CKA_VALUE is not an X.509 certificate: {e}")))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?;
    spki_canonical(&spki)
}

/// Canonical DER SPKI from `CKA_EC_POINT`, which is normally a DER OCTET STRING wrapping the
/// SEC1 point; some providers return the raw point.
pub fn p256_spki_from_ec_point(ec_point: &[u8]) -> Result<Vec<u8>> {
    // A raw uncompressed point also starts with 0x04, so fall back to raw if unwrapping fails.
    let key = <&OctetStringRef>::from_der(ec_point)
        .ok()
        .and_then(|o| p256::PublicKey::from_sec1_bytes(o.as_bytes()).ok())
        .map_or_else(|| p256::PublicKey::from_sec1_bytes(ec_point), Ok)
        .map_err(|e| KmError::Conflict(format!("CKA_EC_POINT is not a P-256 point: {e}")))?;
    encode(&key)
}

fn encode(key: &p256::PublicKey) -> Result<Vec<u8>> {
    Ok(key
        .to_public_key_der()
        .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?
        .as_bytes()
        .to_vec())
}

/// DER of the secp256r1 OID, as used in `CKA_EC_PARAMS`.
pub const SECP256R1_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn sri_of_empty() {
        assert_eq!(sri(b""), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn spec_digest_ignores_attribute_order_but_not_values() {
        let obj = ObjectCfg {
            class: "CKO_PRIVATE_KEY".into(),
            key_type: "CKK_EC".into(),
            curve: Some("secp256r1".into()),
            value_len: None,
            modulus_bits: None,
        };
        let mk = |pairs: &[(&str, bool)]| SpecCfg {
            object: "o".into(),
            attributes: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect::<BTreeMap<_, _>>(),
            tokens: BTreeMap::new(),
        };
        let a = spec_digest(&obj, &mk(&[("CKA_SIGN", true), ("CKA_SENSITIVE", true)]));
        let b = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", true), ("CKA_SIGN", true)]));
        let c = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", false), ("CKA_SIGN", true)]));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ec_point_wrapped_and_raw_agree() {
        let sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let raw = sk.public_key().to_sec1_bytes().to_vec();
        let mut wrapped = vec![0x04, raw.len() as u8];
        wrapped.extend_from_slice(&raw);
        let a = p256_spki_from_ec_point(&raw).unwrap();
        let b = p256_spki_from_ec_point(&wrapped).unwrap();
        assert_eq!(a, b);
        assert_eq!(spki_canonical(&a).unwrap(), a);
    }

    #[test]
    fn rsa_spki_roundtrips() {
        let n = [0xc5u8; 256];
        let a = rsa_spki(&n, &[1, 0, 1]).unwrap();
        assert_eq!(spki_canonical(&a).unwrap(), a);
    }
}
