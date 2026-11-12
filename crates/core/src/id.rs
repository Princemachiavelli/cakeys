//! CA-ID computation: SRI rendering, spec digest, SPKI normalisation, commitment labels.
//!
//! Public keys are decoded and re-encoded by the RustCrypto crates (`p256`, `p384`, `p521`,
//! `ed25519-dalek`, `ed448`, `rsa`); this module only chooses which one by curve or OID.

use crate::config::{ObjectCfg, SpecCfg};
use crate::error::{KmError, Result};
use base64::Engine;
use p256::pkcs8::der::{asn1::OctetStringRef, Decode, Encode};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};

type Bp256 = p256::elliptic_curve::PublicKey<bp256::BrainpoolP256r1>;
type Bp384 = p256::elliptic_curve::PublicKey<bp384::BrainpoolP384r1>;

/// `sha256-<base64>`: drops straight into a Nix `outputHash`, but nothing depends on it.
pub fn sri(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes))
    )
}

/// Whether `s` is an SRI SHA-256 digest as `sri` writes it: `sha256-` and 32 bytes in padded
/// standard base64.
pub fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .is_some_and(|d| d.len() == 32)
}

/// Hash of the canonical JSON of (object type, policy attributes).
pub fn spec_digest(object: &ObjectCfg, spec: &SpecCfg) -> String {
    let doc = serde_json::json!({
        "v": 1,
        "type": object,
        "attributes": spec.attributes,
    });
    sri(canonical_json(doc).to_string().as_bytes())
}

/// Object keys sorted at every level, inserted in that order: the serialization is the same
/// whether or not serde_json's `preserve_order` feature is enabled somewhere in the build.
fn canonical_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, canonical_json(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(canonical_json).collect()),
        v => v,
    }
}

/// Commitment label for objects the lock does not know yet. The lock records, per object, the
/// label its commitments were computed with, and that recorded value is what verification uses:
/// changing this default never breaks an existing lock (docs/DESIGN.md §3.3).
pub const DEFAULT_COMMITMENT_LABEL: &str = "key-management/v1";

/// Schemes computed from a commitment label (all `Commit` variants).
pub const COMMITMENT_SCHEMES: [&str; 5] = ["commitment", "cmac", "kcv-ecb", "kcv-ecb-dec", "kw"];

/// Input-only aliases for scheme names (CLI and Nix library); a lock always uses the scheme name.
pub const SCHEME_ALIASES: [(&str, &str); 1] = [("pubkeyhash", "rfc7093m4")];

/// The scheme name for `name`, resolving input aliases.
pub fn canonical_scheme(name: &str) -> &str {
    SCHEME_ALIASES.iter().find(|(a, _)| *a == name).map_or(name, |(_, s)| s)
}

/// Every scheme this version defines (§3.1 of docs/DESIGN.md).
pub const KNOWN_SCHEMES: [&str; 8] =
    ["rfc7093m4", "certhash", "valuehash", "commitment", "cmac", "kcv-ecb", "kcv-ecb-dec", "kw"];

/// Hash of an HMAC commitment. A key bound to a hash (`CKK_SHA384_HMAC`, ...) is committed with
/// that hash; generic secrets use SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HmacHash {
    /// The HMAC hash for a secret key type, if it is an HMAC-capable type.
    pub fn for_key_type(key_type: &str) -> Option<HmacHash> {
        match key_type {
            "CKK_GENERIC_SECRET" | "CKK_SHA256_HMAC" => Some(HmacHash::Sha256),
            "CKK_SHA_1_HMAC" => Some(HmacHash::Sha1),
            "CKK_SHA224_HMAC" => Some(HmacHash::Sha224),
            "CKK_SHA384_HMAC" => Some(HmacHash::Sha384),
            "CKK_SHA512_HMAC" => Some(HmacHash::Sha512),
            _ => None,
        }
    }
}

/// Secret-key commitments: a deterministic on-token operation over a public, domain-separated
/// input. Each needs a different key usage bit and gives a different value, so each is its own
/// scheme. The lock stores only SHA-256 of the output (`sri`), never a MAC or ciphertext that
/// could be replayed under the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {
    /// HMAC over the label (`CKA_SIGN`; generic secrets and HMAC key types), with the hash the
    /// key type implies. One scheme: the key type is in the label, so types never share an ID.
    Hmac(HmacHash),
    /// `CKM_AES_CMAC` over the label (`CKA_SIGN`).
    Cmac,
    /// `CKM_AES_ECB` encryption of one block, the first 16 bytes of SHA-256(label): a key check
    /// value (`CKA_ENCRYPT`). Single-block ECB only: a fixed nonce with CTR/GCM would leak.
    KcvEcb,
    /// `CKM_AES_ECB` decryption of one such block (`CKA_DECRYPT`): for decrypt-only keys.
    KcvEcbDecrypt,
    /// `CKM_AES_KEY_WRAP` (RFC 3394, deterministic) of a fixed key, SHA-256(label) (`CKA_WRAP`).
    Kw,
}

impl Commit {
    pub fn scheme(self) -> &'static str {
        match self {
            Commit::Hmac(_) => "commitment",
            Commit::Cmac => "cmac",
            Commit::KcvEcb => "kcv-ecb",
            Commit::KcvEcbDecrypt => "kcv-ecb-dec",
            Commit::Kw => "kw",
        }
    }

    /// Domain-separation label `<commitment label>/<scheme>/<keyType>/<bits>`. The intrinsic type
    /// is mixed in so the same bytes held as two key types never share an ID.
    pub fn label(self, commitment_label: &str, object: &ObjectCfg) -> Vec<u8> {
        format!(
            "{commitment_label}/{}/{}/{}",
            self.scheme(),
            object.key_type,
            object.value_len.unwrap_or(0) * 8
        )
        .into_bytes()
    }

    /// The fixed input the token operates on: the label, or its SHA-256 (truncated to one AES
    /// block for the KCV).
    pub fn input(self, commitment_label: &str, object: &ObjectCfg) -> Vec<u8> {
        let label = self.label(commitment_label, object);
        match self {
            Commit::Hmac(_) | Commit::Cmac => label,
            Commit::KcvEcb | Commit::KcvEcbDecrypt => Sha256::digest(&label)[..16].to_vec(),
            Commit::Kw => Sha256::digest(&label).to_vec(),
        }
    }
}

/// Named curves for `CKK_EC` and `CKK_EC_EDWARDS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
    Secp256k1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    Ed25519,
    Ed448,
}

const ALL_CURVES: [Curve; 8] = [
    Curve::P256,
    Curve::P384,
    Curve::P521,
    Curve::Secp256k1,
    Curve::BrainpoolP256r1,
    Curve::BrainpoolP384r1,
    Curve::Ed25519,
    Curve::Ed448,
];

/// Named curves tokens offer that have no RustCrypto crate to validate and encode them with.
pub const CURVES_WITHOUT_CRATE: [&str; 1] = ["brainpoolP512r1"];

impl Curve {
    /// `curve` in keys.toml, for the given `keyType`.
    pub fn from_cfg(key_type: &str, name: &str) -> Option<Curve> {
        match (key_type, name) {
            ("CKK_EC", "secp256r1" | "prime256v1" | "P-256") => Some(Curve::P256),
            ("CKK_EC", "secp384r1" | "P-384") => Some(Curve::P384),
            ("CKK_EC", "secp521r1" | "P-521") => Some(Curve::P521),
            ("CKK_EC", "secp256k1") => Some(Curve::Secp256k1),
            ("CKK_EC", "brainpoolP256r1") => Some(Curve::BrainpoolP256r1),
            ("CKK_EC", "brainpoolP384r1") => Some(Curve::BrainpoolP384r1),
            ("CKK_EC_EDWARDS", "edwards25519" | "Ed25519") => Some(Curve::Ed25519),
            ("CKK_EC_EDWARDS", "edwards448" | "Ed448") => Some(Curve::Ed448),
            _ => None,
        }
    }

    pub fn edwards(self) -> bool {
        matches!(self, Curve::Ed25519 | Curve::Ed448)
    }

    /// `CKA_EC_PARAMS` used when generating: the DER OID (RFC 5480 / RFC 8410).
    pub fn params(self) -> &'static [u8] {
        match self {
            Curve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            Curve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            Curve::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
            Curve::Secp256k1 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
            Curve::BrainpoolP256r1 => &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
            Curve::BrainpoolP384r1 => &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
            Curve::Ed25519 => &[0x06, 0x03, 0x2b, 0x65, 0x70],
            Curve::Ed448 => &[0x06, 0x03, 0x2b, 0x65, 0x71],
        }
    }

    /// PKCS#11 3.0 also allows Edwards curves as a PrintableString curve name.
    fn params_by_name(self) -> Option<&'static [u8]> {
        match self {
            Curve::Ed25519 => Some(b"\x13\x0cedwards25519"),
            Curve::Ed448 => Some(b"\x13\x0aedwards448"),
            _ => None,
        }
    }

    /// The curve named by a token's `CKA_EC_PARAMS`.
    pub fn from_params(params: &[u8]) -> Option<Curve> {
        ALL_CURVES
            .into_iter()
            .find(|c| c.params() == params || c.params_by_name() == Some(params))
    }

    /// Canonical DER SPKI from `CKA_EC_POINT`. That is normally a DER OCTET STRING wrapping the
    /// point (SEC1 for Weierstrass curves, RFC 8032 for Edwards); some providers return it raw.
    pub fn spki_from_point(self, ec_point: &[u8]) -> Result<Vec<u8>> {
        // A raw point can look like an OCTET STRING, so fall back to raw if unwrapping fails.
        <&OctetStringRef>::from_der(ec_point)
            .ok()
            .and_then(|o| self.spki_from_raw(o.as_bytes()).ok())
            .map_or_else(|| self.spki_from_raw(ec_point), Ok)
    }

    fn spki_from_raw(self, point: &[u8]) -> Result<Vec<u8>> {
        let bad = |e: &dyn std::fmt::Display| KmError::Conflict(format!("CKA_EC_POINT is not a {self:?} point: {e}"));
        match self {
            Curve::P256 => encode(&p256::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::P384 => encode(&p384::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::P521 => encode(&p521::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::Secp256k1 => encode(&k256::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::BrainpoolP256r1 => encode(&Bp256::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::BrainpoolP384r1 => encode(&Bp384::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::Ed25519 => encode(&ed25519_dalek::VerifyingKey::try_from(point).map_err(|e| bad(&e))?),
            // No stable Ed448 point arithmetic crate yet: the encoding is checked for length only.
            Curve::Ed448 => encode(&ed448::pkcs8::PublicKeyBytes(
                point.try_into().map_err(|e| bad(&e))?,
            )),
        }
    }
}

/// Canonical DER SPKI from any SPKI encoding (`CKA_PUBLIC_KEY_INFO`, a certificate): decode
/// with the matching crate and re-encode, so provider encoding quirks never change the hash.
pub fn spki_canonical(spki: &[u8]) -> Result<Vec<u8>> {
    if let Ok(k) = p256::PublicKey::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = p384::PublicKey::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = p521::PublicKey::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = k256::PublicKey::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = Bp256::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = Bp384::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_der(spki) {
        return encode(&k);
    }
    if let Ok(k) = ed448::pkcs8::PublicKeyBytes::from_public_key_der(spki) {
        return encode(&k);
    }
    let key = rsa::PublicKey::from_public_key_der(spki).map_err(|e| {
        KmError::Unsupported(format!(
            "SPKI is not P-256/P-384/P-521, secp256k1, brainpoolP256r1/P384r1, Ed25519/Ed448 or RSA: {e}"
        ))
    })?;
    encode(&key)
}

/// Canonical DER SPKI from `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` (big-endian).
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::new(
        rsa::BoxedUint::from_be_slice_vartime(modulus),
        rsa::BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|e| KmError::Conflict(format!("invalid RSA public key: {e}")))?;
    encode(&key)
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

fn encode(key: &impl EncodePublicKey) -> Result<Vec<u8>> {
    Ok(key
        .to_public_key_der()
        .map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?
        .as_bytes()
        .to_vec())
}
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
        let a = Curve::P256.spki_from_point(&raw).unwrap();
        let b = Curve::P256.spki_from_point(&wrapped).unwrap();
        assert_eq!(a, b);
        assert_eq!(spki_canonical(&a).unwrap(), a);
    }

    #[test]
    fn rsa_spki_roundtrips() {
        let n = [0xc5u8; 256];
        let a = rsa_spki(&n, &[1, 0, 1]).unwrap();
        assert_eq!(spki_canonical(&a).unwrap(), a);
    }

    #[test]
    fn hmac_commitment_label_is_unchanged() {
        let obj = ObjectCfg {
            class: "CKO_SECRET_KEY".into(),
            key_type: "CKK_GENERIC_SECRET".into(),
            curve: None,
            value_len: Some(32),
            modulus_bits: None,
        };
        assert_eq!(
            Commit::Hmac(HmacHash::Sha256).label(DEFAULT_COMMITMENT_LABEL, &obj),
            b"key-management/v1/commitment/CKK_GENERIC_SECRET/256"
        );
        assert_eq!(Commit::KcvEcb.input(DEFAULT_COMMITMENT_LABEL, &obj).len(), 16);
        assert_eq!(Commit::Kw.input(DEFAULT_COMMITMENT_LABEL, &obj).len(), 32);
    }

    #[test]
    fn curve_params_roundtrip_and_match_the_crates() {
        use p256::elliptic_curve::pkcs8::AssociatedOid;
        let oid = |o: p256::pkcs8::ObjectIdentifier| o.to_der().unwrap();
        assert_eq!(Curve::P256.params(), oid(p256::NistP256::OID));
        assert_eq!(Curve::P384.params(), oid(p384::NistP384::OID));
        assert_eq!(Curve::P521.params(), oid(p521::NistP521::OID));
        assert_eq!(Curve::Secp256k1.params(), oid(k256::Secp256k1::OID));
        assert_eq!(Curve::BrainpoolP256r1.params(), oid(bp256::BrainpoolP256r1::OID));
        assert_eq!(Curve::BrainpoolP384r1.params(), oid(bp384::BrainpoolP384r1::OID));
        assert_eq!(Curve::Ed25519.params(), oid(ed25519_dalek::pkcs8::ALGORITHM_OID));
        assert_eq!(Curve::Ed448.params(), oid(ed448::pkcs8::ALGORITHM_OID));
        for c in ALL_CURVES {
            assert_eq!(Curve::from_params(c.params()), Some(c));
        }
        assert_eq!(Curve::from_params(b"\x13\x0cedwards25519"), Some(Curve::Ed25519));
    }

    #[test]
    fn spec_digests_are_pinned() {
        let mk = |class: &str, kt: &str, curve: Option<&str>, vl: Option<u64>, bits: Option<u64>, attrs: &[(&str, bool)]| {
            let o = ObjectCfg {
                class: class.into(),
                key_type: kt.into(),
                curve: curve.map(Into::into),
                value_len: vl,
                modulus_bits: bits,
            };
            let s = SpecCfg {
                object: "x".into(),
                attributes: attrs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                tokens: BTreeMap::new(),
            };
            spec_digest(&o, &s)
        };
        assert_eq!(
            mk("CKO_CERTIFICATE", "CKC_X_509", None, None, None, &[]),
            "sha256-noKljWvl1rKxRb3BFem4wdjP4ssY9O8CaK9GePRzsqk="
        );
        assert_eq!(
            mk("CKO_PRIVATE_KEY", "CKK_RSA", None, None, Some(2048), &[]),
            "sha256-8k3VUT0T/6zvM/Yp6b2isKLrYOrK2vfyd7UWWz/DUiY="
        );
        assert_eq!(
            mk("CKO_PRIVATE_KEY", "CKK_EC", Some("secp256r1"), None, None, &[("CKA_SIGN", true), ("CKA_SENSITIVE", true), ("CKA_EXTRACTABLE", false)]),
            "sha256-ZTVELcTP+fshDL1IjnlOuVcNW/f0rw8a71Ztk5IRwns="
        );
        assert_eq!(
            mk("CKO_SECRET_KEY", "CKK_GENERIC_SECRET", None, Some(32), None, &[("CKA_SIGN", true), ("CKA_EXTRACTABLE", true)]),
            "sha256-itlUiIf3R6LLNeujs4Htvzd/3jwJRS/nxRhr5Cgh+FM="
        );
    }

    /// Known-answer tests: each scheme's definition, pinned. A code or crate change that alters
    /// any of these breaks existing locks, so it must fail here, not in a user's lock. A scheme
    /// whose computation changes needs a new name (docs/DESIGN.md §10).
    #[test]
    fn scheme_definitions_are_pinned() {
        let obj = |kt: &str, len: u64| ObjectCfg {
            class: "CKO_SECRET_KEY".into(),
            key_type: kt.into(),
            curve: None,
            value_len: Some(len),
            modulus_bits: None,
        };
        // What each commitment scheme feeds the token (the token's output is then hashed).
        for (kt, len, c, want) in [
            ("CKK_GENERIC_SECRET", 32, Commit::Hmac(HmacHash::Sha256), "sha256-3gML2yTFq/QAofi+p2ao7a9fEgIbaglLT0YCQcqvjLk="),
            ("CKK_SHA384_HMAC", 48, Commit::Hmac(HmacHash::Sha384), "sha256-HUtAzPAIg8HRIIURRy0TrTY8eNLoxo48/G3LuEDdMbw="),
            ("CKK_AES", 32, Commit::Cmac, "sha256-u42TmSUu/rRjWDQH7LYM7fJHAKe/B81julPRAManfus="),
            ("CKK_AES", 32, Commit::KcvEcb, "sha256-L1W0lzlDj7Pcu44tnVa/ekyQRHsIybF5gUIsG/oi270="),
            ("CKK_AES", 16, Commit::KcvEcbDecrypt, "sha256-Ht1do336beKCgXkt86UdPfbUUdqLPc7Md3/3IybSftI="),
            ("CKK_AES", 32, Commit::Kw, "sha256-woiHkSVHlbF2VQCQbiHKffrxo2ShyBOMzsdtKDPtH7c="),
        ] {
            assert_eq!(sri(&c.input(DEFAULT_COMMITMENT_LABEL, &obj(kt, len))), want, "{kt} {}", c.scheme());
        }
        // rfc7093m4: canonical SPKI from fixed points (compressed secp256k1 input normalizes).
        let unhex = |h: &str| (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
        for (c, point, want) in [
            (Curve::P256, "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3", "sha256-zpfsINQ2YaGbIVyy43ammNC0qiqltMeFTpFr0FCC/O4="),
            (Curve::P384, "04b01bfc4a2d7fe2095e6627cc5caf9abd153d5b551fe7f6da615da9d1bfd101e8d191e85902c0a34eaa3a16e666880b73059f658c4d6a6e57c0959de80109b0fa6b56bd63d1d5701a93d15322f2267a15526641c60cd07c912a6df58aa993d89b", "sha256-lZsez90QHDfJQWpTPfCv+eHf7LY4NpyFH+EQZ4VjmpM="),
            (Curve::P521, "0400e885ae400c9674eeca8cf31f686419a33138db4aae8a20067d62c94d600bb2a48d989aa95f9615d4e5bacdc044e179803072f8f133e115d25e96c556e469bd8ad3000e07af1f79c99b5ac75a49f120cd7e8cc995d00929df0d37d943d81b55a306d6c8c0eedf8732041f03d073625aef81f59ec165a6a8f6a86db7d2aa72536d3c9bb7", "sha256-VALfpeeRcX+xETHLs6jCtUC7CIqf5XNBivx3le/NX6w="),
            (Curve::Secp256k1, "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f", "sha256-GGiTh3jiylXXEKyGdFCFl7SIJeh1A/vhl3c13ILSdfs="),
            (Curve::BrainpoolP256r1, "04028ec4ffd1f989083b4dea1542e8f61d15c28deb3a61ddadffba11ab76d1d8d75eb8e2d46ec7c23353469bd0ed08c292152987e4367f977a3ff80e1a086c4348", "sha256-EUqjIIpLZdllAsykMZpqcQaXQ/2tBFOD7+Yx3QkfTjU="),
            (Curve::BrainpoolP384r1, "0449dd247f168d73664a8f26ace5d9f34aad77f84998edbbcec898f92d30a4548f4d274c98a08d172afd0d5c86342c8efd16522b32f0dbc8afc0a5493b8d7e09237df15ee7a8b257edac927f7b6d0a5a7de561ecfff0151f73b9070e385e8be376", "sha256-StxntL+EMsY/zm/T3hOEDDruXh8aVrTAFM6j1kaknC0="),
            (Curve::Ed25519, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "sha256-BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k="),
        ] {
            assert_eq!(sri(&c.spki_from_point(&unhex(point)).unwrap()), want, "{c:?}");
        }
        assert_eq!(sri(&Curve::Ed448.spki_from_point(&[7u8; 57]).unwrap()), "sha256-cfF15XCGWRqstHtN6A71S40xP0sTzTP+Kbkzd9quwyc=");
        assert_eq!(sri(&rsa_spki(&[0xc5u8; 256], &[1, 0, 1]).unwrap()), "sha256-YAhs9O2fj0M1rDBQoGcFdy9IyFxKRflfglzP6zTtER0=");
    }
}
