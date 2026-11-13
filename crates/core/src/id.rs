//! CA-ID computation: SRI rendering, spec digest, SPKI normalisation, commitment labels.
//!
//! Public keys are decoded and re-encoded by the `RustCrypto` crates (`p256`, `p384`, `p521`,
//! `ed25519-dalek`, `ed448`, `rsa`); this module only chooses which one by curve or OID.

use crate::config::{ObjectCfg, SpecCfg};
use crate::error::{KmError, Result};
use crate::types::KeyType;
use base64::Engine;
use p256::pkcs8::der::{Decode, Encode, asn1::OctetStringRef};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};

type Bp256 = p256::elliptic_curve::PublicKey<bp256::BrainpoolP256r1>;
type Bp384 = p256::elliptic_curve::PublicKey<bp384::BrainpoolP384r1>;

/// `sha256-<base64>`: drops straight into a Nix `outputHash`, but nothing depends on it.
pub fn sri(bytes: &[u8]) -> String {
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes)))
}

/// Whether `s` is an SRI SHA-256 digest as `sri` writes it: `sha256-` and 32 bytes in padded
/// standard base64.
pub fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .is_some_and(|d| d.len() == 32)
}

/// Hash of the canonical JSON of (object type, policy attributes, public-half attributes).
pub fn spec_digest(object: &ObjectCfg, spec: &SpecCfg) -> String {
    let mut doc = serde_json::json!({
        "v": 1,
        "type": object,
        "attributes": spec.attributes,
    });
    // Only when declared, so the digests of specs without it are unchanged.
    if !spec.public_attributes.is_empty() {
        doc["publicAttributes"] = serde_json::json!(spec.public_attributes);
    }
    sri(canonical_json(doc).to_string().as_bytes())
}

/// Object keys sorted at every level, inserted in that order: the serialization is the same
/// whether or not `serde_json`'s `preserve_order` feature is enabled somewhere in the build.
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

/// The identity schemes this version defines (§3.1 of docs/DESIGN.md). The lock keys its IDs by
/// [`Scheme::name`]; it keeps them as strings, so a scheme from a newer cakeys still loads (and
/// is reported as unchecked) instead of failing the whole lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    Rfc7093m4,
    Certhash,
    Valuehash,
    /// HMAC over the commitment label (`Commit::Hmac`).
    Commitment,
    Cmac,
    KcvEcb,
    KcvEcbDec,
    Kw,
    PivAttestation,
    TpmCertify,
}

impl Scheme {
    pub const ALL: [Scheme; 10] = [
        Scheme::Rfc7093m4,
        Scheme::Certhash,
        Scheme::Valuehash,
        Scheme::Commitment,
        Scheme::Cmac,
        Scheme::KcvEcb,
        Scheme::KcvEcbDec,
        Scheme::Kw,
        Scheme::PivAttestation,
        Scheme::TpmCertify,
    ];

    /// Schemes whose computation is deprecated (docs/DESIGN.md §3.1). Identities already locked
    /// under one keep verifying — with a warning — but `realise` never records a new one: a
    /// changed or weakened computation gets a *new* scheme name (§10), so the empty list is the
    /// "nothing is deprecated" state, pinned by test.
    pub const DEPRECATED: [Scheme; 0] = [];

    /// Input-only aliases (CLI and Nix library); a lock always uses the scheme name.
    pub const ALIASES: [(&str, Scheme); 1] = [("pubkeyhash", Scheme::Rfc7093m4)];

    /// The name the lock records.
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Rfc7093m4 => "rfc7093m4",
            Scheme::Certhash => "certhash",
            Scheme::Valuehash => "valuehash",
            Scheme::Commitment => "commitment",
            Scheme::Cmac => "cmac",
            Scheme::KcvEcb => "kcv-ecb",
            Scheme::KcvEcbDec => "kcv-ecb-dec",
            Scheme::Kw => "kw",
            Scheme::PivAttestation => "piv-attestation",
            Scheme::TpmCertify => "tpm-certify",
        }
    }

    /// The scheme a lock names, exactly (no aliases: the lock refuses them).
    pub fn from_name(name: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The scheme a user names on input, resolving aliases.
    pub fn from_input(name: &str) -> Option<Scheme> {
        Scheme::ALIASES.iter().find(|(a, _)| *a == name).map(|(_, s)| *s).or_else(|| Scheme::from_name(name))
    }

    /// Computed from a commitment label (every `Commit` variant).
    pub fn is_commitment(self) -> bool {
        matches!(self, Scheme::Commitment | Scheme::Cmac | Scheme::KcvEcb | Scheme::KcvEcbDec | Scheme::Kw)
    }

    /// Attestation schemes (§3.7 of docs/DESIGN.md): IDs from a vendor- or TPM-signed
    /// attestation of the key. They are *provenance* evidence for one device: the same material
    /// on another token either cannot attest (PIV attests only keys generated on the device) or
    /// attests to a different ID (a TPM's qualified Name names its own hierarchy). So they are
    /// recorded per realisation, never in an object's shared `ids`, and never stand alone: the
    /// realisation must also match a portable scheme, which is what links the same material
    /// across tokens. Unlike the commitment schemes, they take no `commitmentLabel`: their input
    /// is the attestation itself, not a message the token MACs.
    pub fn is_attestation(self) -> bool {
        self.attestation_kind().is_some()
    }

    /// The lock-record `attestation.kind` of an attestation scheme (§3.7): which evidence
    /// produced the ID. One kind per scheme, pinned so a lock names its evidence exactly.
    pub fn attestation_kind(self) -> Option<&'static str> {
        match self {
            Scheme::PivAttestation => Some("yubico-piv"),
            Scheme::TpmCertify => Some("tpm-certify"),
            _ => None,
        }
    }

    /// The attestation scheme a lock-record kind names.
    pub fn from_attestation_kind(kind: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.attestation_kind() == Some(kind))
    }

    pub fn is_deprecated(self) -> bool {
        Scheme::DEPRECATED.contains(&self)
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The canonical encoding shared by the attestation commitment definitions: a domain-separated
/// tag, then each field as a u32 length prefix and its bytes, so no field can bleed into the
/// next (§3.7, §10).
fn attest_encoding(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + fields.len() * 8);
    v.extend_from_slice(tag);
    for f in fields {
        v.extend_from_slice(
            &(u32::try_from(f.len()).expect("an attestation field is far shorter than 4 GiB")).to_le_bytes(),
        );
        v.extend_from_slice(f);
    }
    v
}

/// The `piv-attestation` commitment (§3.7): what a `YubiKey` PIV attestation certificate *asserts*,
/// not its bytes. The certificate is generated on demand with a random serial and a randomized
/// ECDSA signature, so hashing the DER would be unstable; these fields are the stable claims.
/// `issuer_spki` is the device attestation key in slot f9 (pinned per realisation through the
/// verified chain to the Yubico root), `subject_spki` is the attested key — the same public key
/// the object's `rfc7093m4` hashes, which the caller must have checked — and the rest are the
/// Yubico extension values (1.3.6.1.4.1.41482.3.3/.3.7/.3.8/.3.9), empty when the cert omits one.
pub fn piv_attestation_id(
    issuer_spki: &[u8],
    subject_spki: &[u8],
    firmware: &[u8],
    serial: &[u8],
    pin_touch_policy: &[u8],
    formfactor: &[u8],
) -> String {
    sri(&attest_encoding(
        b"cakeys/piv-attestation/v1\0",
        &[issuer_spki, subject_spki, firmware, serial, pin_touch_policy, formfactor],
    ))
}

/// The `tpm-certify` commitment (§3.7): the Name and qualified Name a `TPM2_Certify` statement
/// attests, signed by an Attestation Key. The Name is `nameAlg ‖ H(TPMT_PUBLIC)` — it covers the
/// public key, every `objectAttributes` bit and the `authPolicy` — and the qualified Name places
/// the object in its hierarchy. The qualifying data (host nonce) proves freshness and is
/// verification evidence only: never part of the ID.
pub fn tpm_certify_id(name: &[u8], qualified_name: &[u8]) -> String {
    sri(&attest_encoding(b"cakeys/tpm-certify/v1\0", &[name, qualified_name]))
}

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
    pub fn for_key_type(key_type: KeyType) -> Option<HmacHash> {
        match key_type {
            KeyType::GenericSecret | KeyType::Sha256Hmac => Some(HmacHash::Sha256),
            KeyType::Sha1Hmac => Some(HmacHash::Sha1),
            KeyType::Sha224Hmac => Some(HmacHash::Sha224),
            KeyType::Sha384Hmac => Some(HmacHash::Sha384),
            KeyType::Sha512Hmac => Some(HmacHash::Sha512),
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
    pub fn scheme(self) -> Scheme {
        match self {
            Commit::Hmac(_) => Scheme::Commitment,
            Commit::Cmac => Scheme::Cmac,
            Commit::KcvEcb => Scheme::KcvEcb,
            Commit::KcvEcbDecrypt => Scheme::KcvEcbDec,
            Commit::Kw => Scheme::Kw,
        }
    }

    /// Domain-separation label `<commitment label>/<scheme>/<keyType>/<bits>`. The intrinsic type
    /// is mixed in so the same bytes held as two key types never share an ID.
    pub fn label(self, commitment_label: &str, object: &ObjectCfg) -> Vec<u8> {
        format!(
            "{commitment_label}/{}/{}/{}",
            self.scheme(),
            object.key_type.map_or("", KeyType::name),
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

/// Named curves tokens offer that have no `RustCrypto` crate to validate and encode them with.
pub const CURVES_WITHOUT_CRATE: [&str; 1] = ["brainpoolP512r1"];

impl Curve {
    /// `curve` in keys.toml, for the given `keyType`.
    pub fn from_cfg(key_type: KeyType, name: &str) -> Option<Curve> {
        match (key_type, name) {
            (KeyType::Ec, "secp256r1" | "prime256v1" | "P-256") => Some(Curve::P256),
            (KeyType::Ec, "secp384r1" | "P-384") => Some(Curve::P384),
            (KeyType::Ec, "secp521r1" | "P-521") => Some(Curve::P521),
            (KeyType::Ec, "secp256k1") => Some(Curve::Secp256k1),
            (KeyType::Ec, "brainpoolP256r1") => Some(Curve::BrainpoolP256r1),
            (KeyType::Ec, "brainpoolP384r1") => Some(Curve::BrainpoolP384r1),
            (KeyType::EcEdwards, "edwards25519" | "Ed25519") => Some(Curve::Ed25519),
            (KeyType::EcEdwards, "edwards448" | "Ed448") => Some(Curve::Ed448),
            _ => None,
        }
    }

    /// The canonical `curve` name, as recorded in the lock.
    pub fn name(self) -> &'static str {
        match self {
            Curve::P256 => "secp256r1",
            Curve::P384 => "secp384r1",
            Curve::P521 => "secp521r1",
            Curve::Secp256k1 => "secp256k1",
            Curve::BrainpoolP256r1 => "brainpoolP256r1",
            Curve::BrainpoolP384r1 => "brainpoolP384r1",
            Curve::Ed25519 => "edwards25519",
            Curve::Ed448 => "edwards448",
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

    /// PKCS#11 3.0 also allows Edwards curves as a `PrintableString` curve name.
    fn params_by_name(self) -> Option<&'static [u8]> {
        match self {
            Curve::Ed25519 => Some(b"\x13\x0cedwards25519"),
            Curve::Ed448 => Some(b"\x13\x0aedwards448"),
            _ => None,
        }
    }

    /// The curve named by a token's `CKA_EC_PARAMS`.
    pub fn from_params(params: &[u8]) -> Option<Curve> {
        ALL_CURVES.into_iter().find(|c| c.params() == params || c.params_by_name() == Some(params))
    }

    /// Canonical DER SPKI from `CKA_EC_POINT`. That is normally a DER OCTET STRING wrapping the
    /// point (SEC1 for Weierstrass curves, RFC 8032 for Edwards); some providers return it raw.
    ///
    /// # Errors
    ///
    /// `Conflict` if the value — wrapped or raw — is not a valid point of this curve.
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
            Curve::Ed448 => encode(&ed448::pkcs8::PublicKeyBytes(point.try_into().map_err(|e| bad(&e))?)),
        }
    }
}

/// Canonical DER SPKI from any SPKI encoding (`CKA_PUBLIC_KEY_INFO`, a certificate): decode
/// with the matching crate and re-encode, so provider encoding quirks never change the hash.
///
/// # Errors
///
/// `Unsupported` if the input is a syntactically valid SPKI of no key type cakeys hashes.
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
///
/// # Errors
///
/// `Conflict` if the values are not a valid RSA public key (for instance, an even modulus).
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::new(
        rsa::BoxedUint::from_be_slice_vartime(modulus),
        rsa::BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|e| KmError::Conflict(format!("invalid RSA public key: {e}")))?;
    encode(&key)
}

/// Canonical DER SPKI of a certificate's subject key: links a certificate to its key object.
///
/// # Errors
///
/// `Conflict` if the value is not a parsable X.509 certificate, or its subject key is one
/// `spki_canonical` refuses (also `Unsupported` in that case).
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
    Ok(key.to_public_key_der().map_err(|e| KmError::Conflict(format!("encoding SPKI: {e}")))?.as_bytes().to_vec())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttrValue;

    /// An object type from its PKCS#11 names (`""`: no key type).
    fn cfg(class: &str, key_type: &str) -> ObjectCfg {
        ObjectCfg::new(class.parse().unwrap(), (!key_type.is_empty()).then(|| key_type.parse().unwrap()))
    }
    use std::collections::BTreeMap;

    #[test]
    fn sri_of_empty() {
        assert_eq!(sri(b""), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn spec_digest_ignores_attribute_order_but_not_values() {
        let obj = ObjectCfg { curve: Some("secp256r1".into()), ..cfg("CKO_PRIVATE_KEY", "CKK_EC") };
        let mk = |pairs: &[(&str, bool)]| SpecCfg {
            object: "o".into(),
            attributes: pairs.iter().map(|(k, v)| (k.to_string(), AttrValue::Bool(*v))).collect::<BTreeMap<_, _>>(),
            public_attributes: BTreeMap::new(),
            tokens: BTreeMap::new(),
        };
        let a = spec_digest(&obj, &mk(&[("CKA_SIGN", true), ("CKA_SENSITIVE", true)]));
        let b = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", true), ("CKA_SIGN", true)]));
        let c = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", false), ("CKA_SIGN", true)]));
        assert_eq!(a, b);
        assert_ne!(a, c);
        // A reordered mechanism list is the same set: the same digest. (`load_config` sorts
        // declared lists through `AttrValue::mechanisms`, so the digest only sees sorted ones.)
        let list = |names: &[&str]| SpecCfg {
            object: "o".into(),
            attributes: [(
                "CKA_ALLOWED_MECHANISMS".to_owned(),
                AttrValue::mechanisms(names.iter().map(std::string::ToString::to_string)),
            )]
            .into_iter()
            .collect(),
            public_attributes: BTreeMap::new(),
            tokens: BTreeMap::new(),
        };
        assert_eq!(
            spec_digest(&obj, &list(&["CKM_ECDSA", "CKM_ECDSA_SHA256"])),
            spec_digest(&obj, &list(&["CKM_ECDSA_SHA256", "CKM_ECDSA"]))
        );
        // `publicAttributes` take part only when declared.
        let mut with_public = mk(&[]);
        with_public.public_attributes.insert("CKA_VERIFY".into(), AttrValue::Bool(true));
        assert_ne!(spec_digest(&obj, &mk(&[])), spec_digest(&obj, &with_public));
    }

    #[test]
    fn ec_point_wrapped_and_raw_agree() {
        let sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let raw = sk.public_key().to_sec1_bytes().to_vec();
        let mut wrapped = vec![0x04, u8::try_from(raw.len()).unwrap()];
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
        let obj = ObjectCfg { value_len: Some(32), ..cfg("CKO_SECRET_KEY", "CKK_GENERIC_SECRET") };
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
        let mk =
            |class: &str, kt: &str, curve: Option<&str>, vl: Option<u64>, bits: Option<u64>, attrs: &[(&str, bool)]| {
                let o = ObjectCfg { curve: curve.map(Into::into), value_len: vl, modulus_bits: bits, ..cfg(class, kt) };
                let s = SpecCfg {
                    object: "x".into(),
                    attributes: attrs.iter().map(|(k, v)| (k.to_string(), AttrValue::Bool(*v))).collect(),
                    public_attributes: BTreeMap::new(),
                    tokens: BTreeMap::new(),
                };
                spec_digest(&o, &s)
            };
        // The certificate type lives in `certificateType` (this digest changed when it did, and
        // is pinned since: the RSA, EC and generic-secret digests below must not move).
        let cert = ObjectCfg { certificate_type: Some("CKC_X_509".into()), ..cfg("CKO_CERTIFICATE", "") };
        let none = SpecCfg {
            object: "x".into(),
            attributes: BTreeMap::new(),
            public_attributes: BTreeMap::new(),
            tokens: BTreeMap::new(),
        };
        assert_eq!(spec_digest(&cert, &none), "sha256-1RYKnSVKlK3XckaD3EScGIoGyQgH4NyCvkrCm7Y6+Cs=");
        assert_eq!(
            mk("CKO_PRIVATE_KEY", "CKK_RSA", None, None, Some(2048), &[]),
            "sha256-8k3VUT0T/6zvM/Yp6b2isKLrYOrK2vfyd7UWWz/DUiY="
        );
        assert_eq!(
            mk(
                "CKO_PRIVATE_KEY",
                "CKK_EC",
                Some("secp256r1"),
                None,
                None,
                &[("CKA_SIGN", true), ("CKA_SENSITIVE", true), ("CKA_EXTRACTABLE", false)]
            ),
            "sha256-ZTVELcTP+fshDL1IjnlOuVcNW/f0rw8a71Ztk5IRwns="
        );
        assert_eq!(
            mk(
                "CKO_SECRET_KEY",
                "CKK_GENERIC_SECRET",
                None,
                Some(32),
                None,
                &[("CKA_SIGN", true), ("CKA_EXTRACTABLE", true)]
            ),
            "sha256-itlUiIf3R6LLNeujs4Htvzd/3jwJRS/nxRhr5Cgh+FM="
        );
    }

    /// Known-answer tests: each scheme's definition, pinned. A code or crate change that alters
    /// any of these breaks existing locks, so it must fail here, not in a user's lock. A scheme
    /// whose computation changes needs a new name (docs/DESIGN.md §10).
    #[test]
    fn scheme_definitions_are_pinned() {
        let obj = |kt: &str, len: u64| ObjectCfg { value_len: Some(len), ..cfg("CKO_SECRET_KEY", kt) };
        // What each commitment scheme feeds the token (the token's output is then hashed).
        for (kt, len, c, want) in [
            (
                "CKK_GENERIC_SECRET",
                32,
                Commit::Hmac(HmacHash::Sha256),
                "sha256-3gML2yTFq/QAofi+p2ao7a9fEgIbaglLT0YCQcqvjLk=",
            ),
            (
                "CKK_SHA384_HMAC",
                48,
                Commit::Hmac(HmacHash::Sha384),
                "sha256-HUtAzPAIg8HRIIURRy0TrTY8eNLoxo48/G3LuEDdMbw=",
            ),
            ("CKK_AES", 32, Commit::Cmac, "sha256-u42TmSUu/rRjWDQH7LYM7fJHAKe/B81julPRAManfus="),
            ("CKK_AES", 32, Commit::KcvEcb, "sha256-L1W0lzlDj7Pcu44tnVa/ekyQRHsIybF5gUIsG/oi270="),
            ("CKK_AES", 16, Commit::KcvEcbDecrypt, "sha256-Ht1do336beKCgXkt86UdPfbUUdqLPc7Md3/3IybSftI="),
            ("CKK_AES", 32, Commit::Kw, "sha256-woiHkSVHlbF2VQCQbiHKffrxo2ShyBOMzsdtKDPtH7c="),
        ] {
            assert_eq!(sri(&c.input(DEFAULT_COMMITMENT_LABEL, &obj(kt, len))), want, "{kt} {}", c.scheme());
        }
        // rfc7093m4: canonical SPKI from fixed points (compressed secp256k1 input normalizes).
        let unhex = |h: &str| {
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()
        };
        for (c, point, want) in [
            (
                Curve::P256,
                "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3",
                "sha256-zpfsINQ2YaGbIVyy43ammNC0qiqltMeFTpFr0FCC/O4=",
            ),
            (
                Curve::P384,
                "04b01bfc4a2d7fe2095e6627cc5caf9abd153d5b551fe7f6da615da9d1bfd101e8d191e85902c0a34eaa3a16e666880b73059f658c4d6a6e57c0959de80109b0fa6b56bd63d1d5701a93d15322f2267a15526641c60cd07c912a6df58aa993d89b",
                "sha256-lZsez90QHDfJQWpTPfCv+eHf7LY4NpyFH+EQZ4VjmpM=",
            ),
            (
                Curve::P521,
                "0400e885ae400c9674eeca8cf31f686419a33138db4aae8a20067d62c94d600bb2a48d989aa95f9615d4e5bacdc044e179803072f8f133e115d25e96c556e469bd8ad3000e07af1f79c99b5ac75a49f120cd7e8cc995d00929df0d37d943d81b55a306d6c8c0eedf8732041f03d073625aef81f59ec165a6a8f6a86db7d2aa72536d3c9bb7",
                "sha256-VALfpeeRcX+xETHLs6jCtUC7CIqf5XNBivx3le/NX6w=",
            ),
            (
                Curve::Secp256k1,
                "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
                "sha256-GGiTh3jiylXXEKyGdFCFl7SIJeh1A/vhl3c13ILSdfs=",
            ),
            (
                Curve::BrainpoolP256r1,
                "04028ec4ffd1f989083b4dea1542e8f61d15c28deb3a61ddadffba11ab76d1d8d75eb8e2d46ec7c23353469bd0ed08c292152987e4367f977a3ff80e1a086c4348",
                "sha256-EUqjIIpLZdllAsykMZpqcQaXQ/2tBFOD7+Yx3QkfTjU=",
            ),
            (
                Curve::BrainpoolP384r1,
                "0449dd247f168d73664a8f26ace5d9f34aad77f84998edbbcec898f92d30a4548f4d274c98a08d172afd0d5c86342c8efd16522b32f0dbc8afc0a5493b8d7e09237df15ee7a8b257edac927f7b6d0a5a7de561ecfff0151f73b9070e385e8be376",
                "sha256-StxntL+EMsY/zm/T3hOEDDruXh8aVrTAFM6j1kaknC0=",
            ),
            (
                Curve::Ed25519,
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "sha256-BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=",
            ),
        ] {
            assert_eq!(sri(&c.spki_from_point(&unhex(point)).unwrap()), want, "{c:?}");
        }
        assert_eq!(
            sri(&Curve::Ed448.spki_from_point(&[7u8; 57]).unwrap()),
            "sha256-cfF15XCGWRqstHtN6A71S40xP0sTzTP+Kbkzd9quwyc="
        );
        assert_eq!(
            sri(&rsa_spki(&[0xc5u8; 256], &[1, 0, 1]).unwrap()),
            "sha256-YAhs9O2fj0M1rDBQoGcFdy9IyFxKRflfglzP6zTtER0="
        );
    }

    /// The deprecation register (docs/DESIGN.md §3.1, finding S15): empty today, so adding a name
    /// is a deliberate, reviewed diff; and a deprecated name must be one this cakeys knows.
    #[test]
    fn the_deprecation_register_is_pinned() {
        assert!(Scheme::DEPRECATED.is_empty(), "deprecating a scheme is a design decision; see docs/DESIGN.md §3.1");
    }

    /// Scheme names are lock keys: renaming one breaks every lock that records it (§10).
    #[test]
    fn scheme_names_are_pinned() {
        let names: Vec<&str> = Scheme::ALL.into_iter().map(Scheme::name).collect();
        assert_eq!(
            names,
            [
                "rfc7093m4",
                "certhash",
                "valuehash",
                "commitment",
                "cmac",
                "kcv-ecb",
                "kcv-ecb-dec",
                "kw",
                "piv-attestation",
                "tpm-certify"
            ]
        );
        let commitments: Vec<&str> = Scheme::ALL.into_iter().filter(|s| s.is_commitment()).map(Scheme::name).collect();
        assert_eq!(commitments, ["commitment", "cmac", "kcv-ecb", "kcv-ecb-dec", "kw"]);
        assert_eq!(Scheme::from_input("pubkeyhash"), Some(Scheme::Rfc7093m4));
        assert_eq!(Scheme::from_name("pubkeyhash"), None, "a lock never uses an alias");
    }

    /// The attestation commitment definitions (docs/DESIGN.md §3.7, §10): each scheme's canonical
    /// input, pinned. The attestations are verified evidence — Yubico PIV certificate chain,
    /// `TPM2_Certify` over the object's Name — and the canonical encoding below is what an ID is
    /// the SHA-256 of, so a change here breaks locks and must be a new scheme name instead.
    #[test]
    fn attestation_definitions_are_pinned() {
        let kinds: Vec<(&str, &str)> =
            Scheme::ALL.into_iter().filter_map(|s| Some((s.name(), s.attestation_kind()?))).collect();
        assert_eq!(kinds, [("piv-attestation", "yubico-piv"), ("tpm-certify", "tpm-certify")]);
        // piv-attestation: domain tag, then issuer SPKI (f9 device key), subject SPKI (the key),
        // firmware (1.3.6.1.4.1.41482.3.3), serial (.3.7), PIN/touch policy (.3.8), formfactor
        // (.3.9) — length-prefixed in that order, absent extensions as empty fields.
        assert_eq!(
            piv_attestation_id(b"issuer", b"subject", b"\x05\x07\x04", b"\x00\x01\x02\x03", b"\x04\x01", b"\x05"),
            "sha256-Ag0O41w4o5kTLdmBZotdL9DKXHQKn36fPRTUWXLpTJY="
        );
        // tpm-certify: domain tag, then the attested Name (nameAlg tag + H(TPMT_PUBLIC)) and the
        // qualified Name. The freshness nonce is verification evidence and never part of the ID.
        assert_eq!(
            tpm_certify_id(b"\x00\x0bname", b"\x00\x0bqn"),
            "sha256-gtESMfaa12qwnzF1o9xnvKzbZUFlO7WOTHi4aj52aq0="
        );
    }
}
