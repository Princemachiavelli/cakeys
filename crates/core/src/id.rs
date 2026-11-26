//! The computation of CA-IDs: the SRI encoding, the spec digest, the normalisation of an SPKI,
//! and the commitment labels.
//!
//! The `RustCrypto` crates (`p256`, `p384`, `p521`, `ed25519-dalek`, `ed448`, `rsa`) decode and
//! re-encode the public keys. This module only chooses which crate to use, by the curve or by the
//! OID.

use crate::Check;
use crate::config::{ObjectCfg, SpecCfg};
use crate::error::{KmError, Reason, Result};
use crate::types::KeyType;
use base64::Engine;
use der::{Decode, Encode, asn1::OctetStringRef};
use pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};

type Bp256 = p256::elliptic_curve::PublicKey<bp256::BrainpoolP256r1>;
type Bp384 = p256::elliptic_curve::PublicKey<bp384::BrainpoolP384r1>;

/// Returns the SRI form `sha256-<base64>` of the SHA-256 of `bytes`. A Nix `outputHash` accepts
/// this form as it is, but no code depends on that.
#[must_use]
pub fn sri(bytes: &[u8]) -> String {
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes)))
}

/// Returns whether `s` is an SRI SHA-256 digest in the form that `sri` writes: `sha256-` followed
/// by 32 bytes in padded standard base64.
#[must_use]
pub fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .is_some_and(|d| d.len() == 32)
}

/// Returns the SRI hash of the canonical JSON (RFC 8785, JCS) of the object type, the policy
/// attributes and the attributes of the public half.
///
/// # Panics
///
/// Never panics, because the document holds only strings, booleans and small integers, which
/// always canonicalize.
#[must_use]
pub fn spec_digest(object: &ObjectCfg, spec: &SpecCfg) -> String {
    let mut doc = serde_json::json!({
        "v": 1,
        "type": object,
        "attributes": spec.attributes,
    });
    // The public attributes are added only when the spec declares them, so that the digests of
    // the specs without them did not change when this field was introduced.
    if !spec.public_attributes.is_empty() {
        doc["publicAttributes"] = serde_json::json!(spec.public_attributes);
    }
    // RFC 8785 (JCS) sorts the keys at every level and writes no whitespace. The document holds
    // only strings, booleans and small integers, which every JSON library serializes in the same
    // way.
    sri(serde_jcs::to_string(&doc).expect("a JSON value of strings, booleans and integers canonicalizes").as_bytes())
}

/// The commitment label for the objects that the lock does not record yet. The lock records, for
/// each object, the label with which its commitments were computed, and verification uses that
/// recorded label. So a change of this default never breaks an existing lock (docs/DESIGN.md
/// §3.3).
pub const DEFAULT_COMMITMENT_LABEL: &str = "key-management/v1";

/// The identity schemes that this version defines (§3.1 of docs/DESIGN.md). The lock keys its IDs
/// by [`Scheme::name`]. It stores the keys as strings, so that a lock with a scheme from a newer
/// cakeys still loads, and the run reports that scheme as not checked instead of refusing the
/// whole lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    /// RFC 7093 §2 method 4: the SHA-256 of the canonical `SubjectPublicKeyInfo`.
    Rfc7093m4,
    /// The SHA-256 of a certificate's DER.
    Certhash,
    /// The SHA-256 of a data object's `CKA_VALUE`. For a private data object, this scheme is
    /// computed only when its spec declares `CKA_PRIVATE = true` (docs/DESIGN.md §8.2).
    Valuehash,
    /// An HMAC over the commitment label (`Commit::Hmac`).
    Commitment,
    /// An AES-CMAC over the commitment label (`Commit::Cmac`).
    Cmac,
    /// The ECB encryption (AES or DES3) of one block derived from the label, which is a key check
    /// value (`Commit::KcvEcb`).
    KcvEcb,
    /// The ECB decryption of that block, for keys that can only decrypt (`Commit::KcvEcbDecrypt`).
    KcvEcbDec,
    /// The RFC 3394 key wrap of a fixed key derived from the label (`Commit::Kw`).
    Kw,
    /// A `YubiKey` PIV attestation, verified to the pinned Yubico root (recorded for each
    /// realisation).
    PivAttestation,
    /// A native `TPM2_Certify`, verified against a provisioned Attestation Key (recorded for each
    /// realisation).
    TpmCertify,
}

impl Scheme {
    /// Every scheme, in declaration order.
    pub(crate) const ALL: [Scheme; 10] = [
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

    /// The schemes whose computation is deprecated (docs/DESIGN.md §3.1). An identity that the
    /// lock already records under such a scheme still verifies, with a warning, but `lock` never
    /// records a new one. A changed or weakened computation gets a *new* scheme name (§10). The
    /// list is empty because nothing is deprecated now, and a test checks that.
    pub const DEPRECATED: [Scheme; 0] = [];

    /// The aliases that only the input accepts (the command line and the Nix library). A lock
    /// always uses the scheme name.
    pub const ALIASES: [(&str, Scheme); 1] = [("pubkeyhash", Scheme::Rfc7093m4)];

    /// Returns the name that the lock records.
    #[must_use]
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

    /// Returns the scheme with exactly this name. Aliases are not accepted, because the lock
    /// refuses them.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Returns the scheme that a user names on input, and resolves an alias to its scheme.
    #[must_use]
    pub fn from_input(name: &str) -> Option<Scheme> {
        Scheme::ALIASES.iter().find(|(a, _)| *a == name).map(|(_, s)| *s).or_else(|| Scheme::from_name(name))
    }

    /// Returns whether the scheme is computed from a commitment label (every `Commit` variant).
    #[must_use]
    pub fn is_commitment(self) -> bool {
        matches!(self, Scheme::Commitment | Scheme::Cmac | Scheme::KcvEcb | Scheme::KcvEcbDec | Scheme::Kw)
    }

    /// Returns whether the scheme is an attestation scheme (§3.7 of docs/DESIGN.md). An
    /// attestation scheme computes an ID from an attestation of the key that a vendor or a TPM
    /// signed. Such an ID is *provenance* evidence for one device. The same material on another
    /// token either cannot be attested (PIV attests only keys that the device generated) or gets
    /// a different ID (a TPM's qualified Name names the TPM's own hierarchy). So these IDs are
    /// recorded for each realisation and never in an object's `ids`, which every token shares.
    /// They are also never the only scheme: the realisation must also match a portable scheme,
    /// because only a portable scheme links the same material on different tokens. Unlike the
    /// commitment schemes, they use no `commitmentLabel`, because their input is the attestation
    /// itself and not a message of which the token computes a MAC.
    #[must_use]
    pub fn is_attestation(self) -> bool {
        self.attestation_kind().is_some()
    }

    /// Returns the `attestation.kind` that the lock records for an attestation scheme (§3.7),
    /// which names the evidence that produced the ID. Each scheme has exactly one kind, and the
    /// kind never changes, so a lock names its evidence exactly.
    #[must_use]
    pub fn attestation_kind(self) -> Option<&'static str> {
        match self {
            Scheme::PivAttestation => Some("yubico-piv"),
            Scheme::TpmCertify => Some("tpm-certify"),
            _ => None,
        }
    }

    /// Returns the attestation scheme that an `attestation.kind` in the lock names.
    #[must_use]
    pub fn from_attestation_kind(kind: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.attestation_kind() == Some(kind))
    }

    /// Returns whether the scheme is listed in [`Scheme::DEPRECATED`]. Such a scheme verifies with
    /// a warning, and the lock never records a new ID of it.
    #[must_use]
    pub(crate) fn is_deprecated(self) -> bool {
        Scheme::DEPRECATED.contains(&self)
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The canonical encoding that the definitions of the attestation commitments share: a tag for
/// domain separation, then each field as a u32 length prefix followed by its bytes. The length
/// prefix ensures that the bytes of one field can never be read as part of the next field (§3.7,
/// §10).
pub(crate) fn attest_encoding(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
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

/// The `piv-attestation` commitment (§3.7). It hashes what a `YubiKey` PIV attestation
/// certificate *asserts*, not the certificate's bytes. The device generates the certificate on
/// demand, with a random serial number and a randomized ECDSA signature, so a hash of the DER
/// would differ each time. These fields are the claims that stay the same. `issuer_spki` is the
/// device attestation key in slot f9, which is pinned for each realisation through the verified
/// chain to the Yubico root. `subject_spki` is the attested key, which is the same public key
/// that the object's `rfc7093m4` hashes; the caller must have checked that. The other fields are
/// the values of the Yubico extensions (1.3.6.1.4.1.41482.3.3, .3.7, .3.8 and .3.9), and each is
/// empty when the certificate omits that extension.
#[must_use]
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

/// The `tpm-certify` commitment (§3.7): the Name and the qualified Name that a `TPM2_Certify`
/// statement, signed by an Attestation Key, attests. The Name is `nameAlg ‖ H(TPMT_PUBLIC)`, so it
/// covers the public key, every `objectAttributes` bit and the `authPolicy`. The qualified Name
/// places the object in its hierarchy. The qualifying data (the host's nonce) proves that the
/// statement is fresh. It is used only during verification and is never part of the ID.
#[must_use]
pub fn tpm_certify_id(name: &[u8], qualified_name: &[u8]) -> String {
    sri(&attest_encoding(b"cakeys/tpm-certify/v1\0", &[name, qualified_name]))
}

/// The hash of an HMAC commitment. A key type that is bound to a hash (`CKK_SHA384_HMAC`, ...)
/// computes its commitment with that hash. A generic secret uses SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacHash {
    /// SHA-1 (`CKK_SHA_1_HMAC`).
    Sha1,
    /// SHA-224 (`CKK_SHA224_HMAC`).
    Sha224,
    /// SHA-256: `CKK_SHA256_HMAC` and generic secrets.
    Sha256,
    /// SHA-384 (`CKK_SHA384_HMAC`).
    Sha384,
    /// SHA-512 (`CKK_SHA512_HMAC`).
    Sha512,
}

impl HmacHash {
    /// Returns the HMAC hash for a secret key type, or `None` if the type cannot compute an HMAC.
    #[must_use]
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

/// The block cipher of a key check value (`Commit::KcvEcb`, `Commit::KcvEcbDecrypt`). The key type
/// determines the cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCipher {
    /// AES (`CKK_AES`, `CKM_AES_ECB`), with 16-byte blocks.
    Aes,
    /// Three-key Triple DES (`CKK_DES3`, `CKM_DES3_ECB`), with 8-byte blocks.
    Des3,
}

impl BlockCipher {
    /// Returns the block cipher of a secret key type, or `None` if the type is not a block
    /// cipher.
    #[must_use]
    pub fn for_key_type(key_type: KeyType) -> Option<BlockCipher> {
        match key_type {
            KeyType::Aes => Some(BlockCipher::Aes),
            KeyType::Des3 => Some(BlockCipher::Des3),
            _ => None,
        }
    }

    /// Returns the key type of this cipher.
    #[must_use]
    pub fn key_type(self) -> KeyType {
        match self {
            BlockCipher::Aes => KeyType::Aes,
            BlockCipher::Des3 => KeyType::Des3,
        }
    }

    /// Returns the block length in bytes, which is the length of the input that a key check value
    /// encrypts.
    #[must_use]
    pub fn block_len(self) -> usize {
        match self {
            BlockCipher::Aes => 16,
            BlockCipher::Des3 => 8,
        }
    }
}

/// The commitments of a secret key: a deterministic operation on the token over a public input
/// with domain separation. Each commitment needs a different key usage attribute and gives a
/// different value, so each one is a separate scheme. The lock stores only the SHA-256 of the
/// output (`sri`), and never a MAC or a ciphertext that someone could replay as an output of the
/// key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {
    /// An HMAC over the label (`CKA_SIGN`; for generic secrets and HMAC key types), with the hash
    /// that the key type determines. All the hashes share one scheme, because the key type is in
    /// the label, so two key types never share an ID.
    Hmac(HmacHash),
    /// A `CKM_AES_CMAC` over the label (`CKA_SIGN`).
    Cmac,
    /// The ECB encryption (`CKM_AES_ECB`, `CKM_DES3_ECB`) of one block, which consists of the first
    /// block-length bytes of SHA-256(label). This is a key check value (`CKA_ENCRYPT`). Only
    /// single-block ECB is used, because CTR or GCM with a fixed nonce would leak information
    /// about the key. Both ciphers share one scheme, as the HMAC hashes do, because the key type
    /// is in the label. This is not the payment industry's KCV (the key's encryption of a zero
    /// block). That block contains no label and no key type, and HSMs give it out freely. The
    /// lock's hash of a whole block also could not be compared with the three bytes that are
    /// printed for a KCV.
    KcvEcb(BlockCipher),
    /// The ECB decryption of one such block (`CKA_DECRYPT`), for keys that can only decrypt.
    KcvEcbDecrypt(BlockCipher),
    /// The `CKM_AES_KEY_WRAP` (RFC 3394, deterministic) of a fixed key, SHA-256(label)
    /// (`CKA_WRAP`).
    Kw,
}

impl Commit {
    /// Returns the scheme under which this commitment's ID is recorded.
    #[must_use]
    pub fn scheme(self) -> Scheme {
        match self {
            Commit::Hmac(_) => Scheme::Commitment,
            Commit::Cmac => Scheme::Cmac,
            Commit::KcvEcb(_) => Scheme::KcvEcb,
            Commit::KcvEcbDecrypt(_) => Scheme::KcvEcbDec,
            Commit::Kw => Scheme::Kw,
        }
    }

    /// Returns the usage attribute that a spec must declare to have this commitment computed
    /// (docs/DESIGN.md §3.1).
    #[must_use]
    pub fn usage(self) -> &'static str {
        match self {
            Commit::Hmac(_) | Commit::Cmac => "CKA_SIGN",
            Commit::KcvEcb(_) => "CKA_ENCRYPT",
            Commit::KcvEcbDecrypt(_) => "CKA_DECRYPT",
            Commit::Kw => "CKA_WRAP",
        }
    }

    /// Returns the kind by which a profile's `commit.<kind>.<key type>.<bytes>` rows name this
    /// commitment (`cakeys_names::CommitKind`, whose table gives the kind's name and the
    /// mechanism that it runs). The kind is the scheme's own name, with the HMAC's hash added for
    /// an HMAC. The hash is added because one scheme covers every hash, and a generic secret does
    /// not determine the hash. The cipher of a check value is not in the kind, because it is the
    /// row's key type, as it is in the label.
    #[must_use]
    pub fn kind(self) -> cakeys_names::CommitKind {
        use cakeys_names::CommitKind as K;
        match self {
            Commit::Hmac(HmacHash::Sha1) => K::HmacSha1,
            Commit::Hmac(HmacHash::Sha224) => K::HmacSha224,
            Commit::Hmac(HmacHash::Sha256) => K::HmacSha256,
            Commit::Hmac(HmacHash::Sha384) => K::HmacSha384,
            Commit::Hmac(HmacHash::Sha512) => K::HmacSha512,
            Commit::Cmac => K::Cmac,
            Commit::KcvEcb(_) => K::KcvEcb,
            Commit::KcvEcbDecrypt(_) => K::KcvEcbDec,
            Commit::Kw => K::Kw,
        }
    }

    /// Returns the `CKM_` name of the mechanism that the commitment runs. A declared
    /// `CKA_ALLOWED_MECHANISMS` must include it, cakeys-pkcs11's `commit_mechanism` asks the token
    /// for it, and a `commit.*` row was measured with it. It is the mechanism of
    /// [`Commit::kind`], with a check value's cipher.
    #[must_use]
    pub fn mechanism(self) -> &'static str {
        let key_type = match self {
            Commit::KcvEcb(c) | Commit::KcvEcbDecrypt(c) => c.key_type().name(),
            // These commitments have no cipher, so the kind alone names the mechanism.
            Commit::Hmac(_) | Commit::Cmac | Commit::Kw => "",
        };
        self.kind().mechanism(key_type)
    }

    /// Returns the name of [`Commit::kind`], which is the name that a `commit.*` row uses (review
    /// 2026-11-23 A-9: there is one table of names, and the profiles have no names of their own).
    #[must_use]
    pub fn profile_kind(self) -> &'static str {
        self.kind().name()
    }

    /// Returns the label for domain separation, `<commitment label>/<scheme>/<keyType>/<bits>`.
    /// The label includes the intrinsic type, so that the same bytes held as two key types never
    /// share an ID.
    pub fn label(self, commitment_label: &str, object: &ObjectCfg) -> Vec<u8> {
        format!(
            "{commitment_label}/{}/{}/{}",
            self.scheme(),
            object.key_type.map_or("", KeyType::name),
            object.value_len.unwrap_or(0) * 8
        )
        .into_bytes()
    }

    /// Returns the fixed input on which the token operates: the label, or the SHA-256 of the label
    /// (truncated to one block of the cipher for a key check value).
    #[must_use]
    pub fn input(self, commitment_label: &str, object: &ObjectCfg) -> Vec<u8> {
        let label = self.label(commitment_label, object);
        match self {
            Commit::Hmac(_) | Commit::Cmac => label,
            Commit::KcvEcb(c) | Commit::KcvEcbDecrypt(c) => Sha256::digest(&label)[..c.block_len()].to_vec(),
            Commit::Kw => Sha256::digest(&label).to_vec(),
        }
    }
}

/// The named curves for `CKK_EC` and `CKK_EC_EDWARDS`: the curves of `cakeys_names::Curve` for
/// which core has a key type (`in_core`). The table of `cakeys_names::Curve` gives each curve its
/// names, its parameters and its ECDSA hash. This enum holds only the curves with which core
/// computes, so a curve without a key type in core (a Montgomery curve) cannot reach a key here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (`secp256r1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
    /// `secp256k1`.
    Secp256k1,
    /// `brainpoolP256r1`.
    BrainpoolP256r1,
    /// `brainpoolP384r1`.
    BrainpoolP384r1,
    /// Ed25519 (`edwards25519`, `CKK_EC_EDWARDS`).
    Ed25519,
    /// Ed448 (`edwards448`, `CKK_EC_EDWARDS`).
    Ed448,
}

/// The named curves that tokens offer and for which no `RustCrypto` crate exists to validate and
/// encode the keys.
pub const CURVES_WITHOUT_CRATE: [&str; 1] = ["brainpoolP512r1"];

/// Converts a curve to its entry in the names table, which gives the curve's names and its ECDSA
/// hash (`HashAlg::for_curve` uses this conversion for a curve of core).
impl From<Curve> for cakeys_names::Curve {
    fn from(c: Curve) -> Self {
        use cakeys_names::Curve as N;
        match c {
            Curve::P256 => N::P256,
            Curve::P384 => N::P384,
            Curve::P521 => N::P521,
            Curve::Secp256k1 => N::Secp256k1,
            Curve::BrainpoolP256r1 => N::BrainpoolP256r1,
            Curve::BrainpoolP384r1 => N::BrainpoolP384r1,
            Curve::Ed25519 => N::Ed25519,
            Curve::Ed448 => N::Ed448,
        }
    }
}

impl Curve {
    /// Every curve for which cakeys has a key type, the Weierstrass curves first and then the
    /// Edwards curves. These are the curves that keys.toml accepts and on which the probe
    /// generates keys (the probe also measures the Montgomery curves). They are the `in_core`
    /// curves of the names table, in the table's order (`the_curves_are_the_names_tables`).
    pub const ALL: [Curve; 8] = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Secp256k1,
        Curve::BrainpoolP256r1,
        Curve::BrainpoolP384r1,
        Curve::Ed25519,
        Curve::Ed448,
    ];

    /// Returns the curve's entry in the names table.
    #[must_use]
    pub fn named(self) -> cakeys_names::Curve {
        self.into()
    }

    /// Parses `curve` in keys.toml for the given `keyType`. It accepts the canonical name, the
    /// display name (`P-256`, `Ed25519`), or OpenSSL's `prime256v1`.
    #[must_use]
    pub fn from_cfg(key_type: KeyType, name: &str) -> Option<Curve> {
        let edwards = match key_type {
            KeyType::Ec => false,
            KeyType::EcEdwards => true,
            _ => return None,
        };
        let named = |c: &Curve| name == c.name() || name == c.display() || (*c == Curve::P256 && name == "prime256v1");
        Curve::ALL.into_iter().find(|c| c.edwards() == edwards && named(c))
    }

    /// Returns the canonical `curve` name, as the lock records it.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.named().name()
    }

    /// Returns whether this is an Edwards curve (`CKK_EC_EDWARDS`) and not a Weierstrass curve
    /// (`CKK_EC`).
    #[must_use]
    pub fn edwards(self) -> bool {
        self.named().family() == cakeys_names::Family::Edwards
    }

    /// Returns the `CKA_EC_PARAMS` that a key generation uses: the DER OID (RFC 5480 or RFC 8410).
    #[must_use]
    pub fn params(self) -> &'static [u8] {
        self.named().params()
    }

    /// Returns the curve name encoded as a `PrintableString`, which PKCS#11 3.0 also allows in
    /// `CKA_EC_PARAMS` for an Edwards curve, or `None` for a curve without that form.
    #[must_use]
    pub fn params_by_name(self) -> Option<&'static [u8]> {
        self.named().params_by_name()
    }

    /// Returns the curve that a token's `CKA_EC_PARAMS` names.
    #[must_use]
    pub fn from_params(params: &[u8]) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.params() == params || c.params_by_name() == Some(params))
    }

    /// Returns the name that messages use for the curve, such as `P-256` or `Ed25519`.
    #[must_use]
    pub fn display(self) -> &'static str {
        self.named().display()
    }
}

/// The size in bits of an RSA modulus (`cakeys_names::modulus_bits`). It counts the significant
/// bits, not the number of bytes times eight.
pub use cakeys_names::modulus_bits;

/// The algorithm of a key, according to its `AlgorithmIdentifier` (ISSUES.md Q20): a key on a
/// curve (including an Edwards curve) or an RSA key. These OIDs select the one parser that reads
/// the key, instead of a trial of each parser in turn, so the parser of the key's own type
/// reports a malformed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    /// `id-ecPublicKey` on a named curve, or `id-Ed25519` / `id-Ed448` (RFC 8410).
    Ec(Curve),
    /// `rsaEncryption`.
    Rsa,
}

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `rsaEncryption` (RFC 8017).
const RSA_ENCRYPTION: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

impl KeyAlg {
    /// Returns the algorithm of the key that a `SubjectPublicKeyInfo` holds.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` for bytes that are not a `SubjectPublicKeyInfo`, or for a key of an
    /// algorithm or a curve that cakeys does not read.
    pub fn of_spki(spki: &[u8]) -> Result<KeyAlg> {
        KeyAlg::read_spki(spki).map(|(alg, _)| alg)
    }

    /// Returns the curve: `Some` for an EC or Edwards key, and `None` for RSA. Together with
    /// [`Self::of_spki`], it returns the curve of the key in a canonical SPKI (review D6, and
    /// 2026-11-23 A-13).
    #[must_use]
    pub fn curve(self) -> Option<Curve> {
        match self {
            KeyAlg::Ec(c) => Some(c),
            KeyAlg::Rsa => None,
        }
    }

    /// Works as [`KeyAlg::of_spki`] and also returns the parsed SPKI, which the parser of the
    /// key's own type reads next, so that the bytes are decoded only once.
    pub(crate) fn read_spki(spki: &[u8]) -> Result<(KeyAlg, pkcs8::SubjectPublicKeyInfoRef<'_>)> {
        let info = pkcs8::SubjectPublicKeyInfoRef::from_der(spki)
            .map_err(|e| KmError::Unsupported(format!("not a SubjectPublicKeyInfo: {e}").into()))?;
        Ok((KeyAlg::of(&info.algorithm)?, info))
    }

    /// Returns the algorithm of the key that a PKCS#8 `PrivateKeyInfo` holds.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`KeyAlg::of_spki`], for a `PrivateKeyInfo`.
    pub fn of_pkcs8(der: &[u8]) -> Result<KeyAlg> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(der)
            .map_err(|e| KmError::Unsupported(format!("not a PKCS#8 PrivateKeyInfo: {e}").into()))?;
        KeyAlg::of(&info.algorithm)
    }

    fn of(alg: &pkcs8::AlgorithmIdentifierRef<'_>) -> Result<KeyAlg> {
        let unread = |what: String| KmError::Unsupported(format!("{what}, which cakeys does not read").into());
        if alg.oid == RSA_ENCRYPTION {
            return Ok(KeyAlg::Rsa);
        }
        if alg.oid == EC_PUBLIC_KEY {
            let params = alg.parameters.and_then(|p| p.to_der().ok());
            return params
                .as_deref()
                .and_then(Curve::from_params)
                .filter(|c| !c.edwards())
                .map(KeyAlg::Ec)
                .ok_or_else(|| unread("an EC key on another curve".into()));
        }
        // The algorithm OID of an Edwards key is the OID of its curve (RFC 8410), which is the
        // value that `Curve::params` holds.
        alg.oid
            .to_der()
            .ok()
            .as_deref()
            .and_then(Curve::from_params)
            .filter(|c| c.edwards())
            .map(KeyAlg::Ec)
            .ok_or_else(|| unread(format!("a key of algorithm {}", alg.oid)))
    }
}

impl Curve {
    /// Returns the canonical DER SPKI for a `CKA_EC_POINT`. That value is normally a DER OCTET
    /// STRING that contains the point (SEC1 for Weierstrass curves, RFC 8032 for Edwards curves),
    /// but some providers return the point without the OCTET STRING.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the value, with or without the OCTET STRING, is not a valid point of
    /// this curve.
    pub fn spki_from_point(self, ec_point: &[u8]) -> Result<Vec<u8>> {
        // A raw point can look like an OCTET STRING, so the value is read as a raw point when the
        // point inside the OCTET STRING does not decode.
        <&OctetStringRef>::from_der(ec_point)
            .ok()
            .and_then(|o| self.spki_from_raw(o.as_bytes()).ok())
            .map_or_else(|| self.spki_from_raw(ec_point), Ok)
    }

    fn spki_from_raw(self, point: &[u8]) -> Result<Vec<u8>> {
        let bad = |e: &dyn std::fmt::Display| {
            KmError::Conflict(Reason::check(Check::PublicKeyType, format!("CKA_EC_POINT is not a {self:?} point: {e}")))
        };
        match self {
            Curve::P256 => encode(&p256::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::P384 => encode(&p384::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::P521 => encode(&p521::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::Secp256k1 => encode(&k256::PublicKey::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::BrainpoolP256r1 => encode(&Bp256::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::BrainpoolP384r1 => encode(&Bp384::from_sec1_bytes(point).map_err(|e| bad(&e))?),
            Curve::Ed25519 => encode(&ed25519_dalek::VerifyingKey::try_from(point).map_err(|e| bad(&e))?),
            // No stable crate for Ed448 point arithmetic exists yet, so only the length of the
            // encoding is checked.
            Curve::Ed448 => encode(&ed448::pkcs8::PublicKeyBytes(point.try_into().map_err(|e| bad(&e))?)),
        }
    }
}

/// Returns the canonical DER SPKI for any encoding of an SPKI (`CKA_PUBLIC_KEY_INFO`, or the SPKI
/// of a certificate). The function decodes the SPKI with the crate for its algorithm and encodes
/// it again, so that differences in how providers encode an SPKI never change the hash.
///
/// # Errors
///
/// Returns `Unsupported` for bytes that are not an SPKI, for an SPKI of a key type that cakeys
/// does not hash ([`KeyAlg::of_spki`]), or for an SPKI that the parser of its algorithm refuses.
/// The error names the parser's reason.
pub fn spki_canonical(spki: &[u8]) -> Result<Vec<u8>> {
    let alg = KeyAlg::of_spki(spki)?;
    let bad = |e: &dyn std::fmt::Display| {
        let what = match alg {
            KeyAlg::Ec(c) => c.display(),
            KeyAlg::Rsa => "RSA",
        };
        KmError::Unsupported(format!("SPKI of a {what} key: {e}").into())
    };
    match alg {
        KeyAlg::Ec(Curve::P256) => encode(&p256::PublicKey::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::P384) => encode(&p384::PublicKey::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::P521) => encode(&p521::PublicKey::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::Secp256k1) => encode(&k256::PublicKey::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::BrainpoolP256r1) => encode(&Bp256::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::BrainpoolP384r1) => encode(&Bp384::from_public_key_der(spki).map_err(|e| bad(&e))?),
        KeyAlg::Ec(Curve::Ed25519) => {
            encode(&ed25519_dalek::VerifyingKey::from_public_key_der(spki).map_err(|e| bad(&e))?)
        }
        KeyAlg::Ec(Curve::Ed448) => {
            encode(&ed448::pkcs8::PublicKeyBytes::from_public_key_der(spki).map_err(|e| bad(&e))?)
        }
        KeyAlg::Rsa => encode(&rsa_of_spki(spki).map_err(|e| bad(&e))?),
    }
}

/// Returns the RSA public key that a DER SPKI holds, whatever its size (`rsa_key`). It is for
/// code that reads a key without computing with it (its identity, its modulus and exponent, or
/// its size). The `rsa` crate's own parser refuses keys outside its limits.
///
/// # Errors
///
/// Returns the reason when the bytes are not an SPKI that holds an RSA key.
pub fn rsa_of_spki(spki: &[u8]) -> std::result::Result<rsa::PublicKey, String> {
    let info = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(spki).map_err(|e| e.to_string())?;
    let bits = info.subject_public_key.as_bytes().ok_or("the key's bits are not whole bytes")?;
    let key = rsa::pkcs1::RsaPublicKeyRef::from_der(bits).map_err(|e| e.to_string())?;
    rsa_key(key.modulus.as_bytes(), key.public_exponent.as_bytes()).map_err(str::to_owned)
}

/// Returns the canonical DER SPKI for a `CKA_MODULUS` and a `CKA_PUBLIC_EXPONENT` (big-endian),
/// of any size.
///
/// # Errors
///
/// Returns `Conflict` if the values cannot be an RSA public key (`rsa_key`).
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let key = rsa_key(modulus, exponent)
        .map_err(|e| KmError::Conflict(Reason::check(Check::PublicKeyType, format!("invalid RSA public key: {e}"))))?;
    encode(&key)
}

/// Returns an RSA public key for a modulus and an exponent (big-endian), whatever its size. The
/// identity is a hash of public bytes and needs no key with which the `rsa` crate would compute,
/// so the limits of that crate (1024 to 8192 bits, and e ≤ 2^33−1) do not apply to cakeys (id.rs
/// F1). For example, a legacy RSA-768 key and an RSA-16384 key both have an identity. The
/// function refuses the values only when they cannot be an RSA key: an even (or zero) modulus,
/// an even exponent, an exponent below 3, or an exponent that is not below the modulus.
fn rsa_key(modulus: &[u8], exponent: &[u8]) -> std::result::Result<rsa::PublicKey, &'static str> {
    // The values are big-endian, so the last byte is the lowest byte. An empty value is zero,
    // which is even.
    let odd = |v: &[u8]| v.last().is_some_and(|b| b & 1 == 1);
    let (n, e) = (rsa::BoxedUint::from_be_slice_vartime(modulus), rsa::BoxedUint::from_be_slice_vartime(exponent));
    if !odd(modulus) {
        return Err("the modulus is even");
    }
    if !odd(exponent) || e < rsa::BoxedUint::from(3u64) {
        return Err("the exponent is even or below 3");
    }
    if e >= n {
        return Err("the exponent is not below the modulus");
    }
    Ok(rsa::PublicKey::new_unchecked(n, e))
}

/// Returns the canonical DER SPKI of a certificate's subject key, which links a certificate to
/// its key object.
///
/// # Errors
///
/// Returns `Conflict` if the value is not an X.509 certificate that parses. Returns `Unsupported`
/// if `spki_canonical` refuses the subject key.
pub fn cert_spki(cert: &[u8]) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert).map_err(|e| {
        KmError::Conflict(Reason::check(
            Check::CertificateDecodes,
            format!("CKA_VALUE is not an X.509 certificate: {e}"),
        ))
    })?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| KmError::Conflict(Reason::check(Check::CertificateDecodes, format!("encoding SPKI: {e}"))))?;
    spki_canonical(&spki)
}

fn encode(key: &impl EncodePublicKey) -> Result<Vec<u8>> {
    Ok(key
        .to_public_key_der()
        .map_err(|e| KmError::Conflict(Reason::check(Check::PublicKeyType, format!("encoding SPKI: {e}"))))?
        .as_bytes()
        .to_vec())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttrValue;

    /// The OIDs of a key determine its type (ISSUES.md Q20). The P-256 parser refuses a P-256 key
    /// whose point is not on the curve, and the error names P-256; earlier, such a key was passed
    /// on to the RSA parser. The error for an algorithm that cakeys does not read names its OID.
    /// The key of every curve is read as a key of that curve.
    #[test]
    fn a_key_is_read_by_the_parser_its_oids_name() {
        let good = p256::SecretKey::from_slice(&[1u8; 32]).unwrap().public_key().to_public_key_der().unwrap();
        assert_eq!(KeyAlg::of_spki(good.as_bytes()).unwrap(), KeyAlg::Ec(Curve::P256));
        let mut off_curve = good.as_bytes().to_vec();
        *off_curve.last_mut().unwrap() ^= 1;
        let e = spki_canonical(&off_curve).unwrap_err();
        assert!(matches!(&e, KmError::Unsupported(m) if m.starts_with("SPKI of a P-256 key")), "{e}");
        // X25519 (1.3.101.110) is a Montgomery key, which no identity scheme reads.
        let x25519 = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]
            .into_iter()
            .chain([9u8; 32])
            .collect::<Vec<u8>>();
        let e = spki_canonical(&x25519).unwrap_err();
        assert!(e.to_string().contains("a key of algorithm 1.3.101.110, which cakeys does not read"), "{e}");
        assert!(KeyAlg::of_spki(b"junk").unwrap_err().to_string().contains("not a SubjectPublicKeyInfo"));
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_public_key_der().unwrap();
        assert_eq!(KeyAlg::of_spki(ed.as_bytes()).unwrap(), KeyAlg::Ec(Curve::Ed25519));
        assert_eq!(spki_canonical(ed.as_bytes()).unwrap(), ed.as_bytes());
    }

    /// Returns an object type with the given PKCS#11 names (`""` means no key type).
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
            migrate: crate::config::SpecMigrateCfg::default(),
            tokens: BTreeMap::new(),
        };
        let a = spec_digest(&obj, &mk(&[("CKA_SIGN", true), ("CKA_SENSITIVE", true)]));
        let b = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", true), ("CKA_SIGN", true)]));
        let c = spec_digest(&obj, &mk(&[("CKA_SENSITIVE", false), ("CKA_SIGN", true)]));
        assert_eq!(a, b);
        assert_ne!(a, c);
        // A mechanism list in a different order is the same set and has the same digest.
        // (`load_config` sorts the declared lists through `AttrValue::mechanisms`, so the digest
        // only receives sorted lists.)
        let list = |names: &[&str]| SpecCfg {
            object: "o".into(),
            attributes: [(
                "CKA_ALLOWED_MECHANISMS".to_owned(),
                AttrValue::mechanisms(names.iter().map(std::string::ToString::to_string)),
            )]
            .into_iter()
            .collect(),
            public_attributes: BTreeMap::new(),
            migrate: crate::config::SpecMigrateCfg::default(),
            tokens: BTreeMap::new(),
        };
        assert_eq!(
            spec_digest(&obj, &list(&["CKM_ECDSA", "CKM_ECDSA_SHA256"])),
            spec_digest(&obj, &list(&["CKM_ECDSA_SHA256", "CKM_ECDSA"]))
        );
        // `publicAttributes` change the digest only when the spec declares them.
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

    /// Every RSA key has an identity, whatever its size or exponent (id.rs F1). The identity is
    /// the same whether it is computed from the modulus or from the SPKI. Where the `rsa` crate's
    /// checked key accepts the key, the encoding is the same bytes as that key's encoding, so no
    /// identity changed. Only values that cannot be an RSA key are refused.
    #[test]
    fn rsa_keys_of_any_size_have_an_identity() {
        let f4 = [1u8, 0, 1];
        let big_e = [0x08u8, 0, 0, 0, 1]; // 2^35 + 1, above rsa's 2^33 - 1
        for (bytes, e) in [(64, &f4[..]), (96, &f4), (128, &f4), (256, &f4), (1024, &f4), (2048, &f4), (256, &big_e)] {
            let n = vec![0xc5u8; bytes];
            let a = rsa_spki(&n, e).unwrap_or_else(|err| panic!("{} bits: {err}", bytes * 8));
            assert_eq!(spki_canonical(&a).unwrap(), a, "{} bits", bytes * 8);
            let checked = rsa::PublicKey::new(
                rsa::BoxedUint::from_be_slice_vartime(&n),
                rsa::BoxedUint::from_be_slice_vartime(e),
            );
            if let Ok(checked) = checked {
                assert_eq!(encode(&checked).unwrap(), a, "{} bits: the identity changed", bytes * 8);
            }
        }
        // Leading zero bytes are not part of the key.
        assert_eq!(
            rsa_spki(&[&[0u8, 0][..], &[0xc5; 96]].concat(), &[0, 1, 0, 1]).unwrap(),
            rsa_spki(&[0xc5; 96], &f4).unwrap()
        );
        let even = [0xc4u8; 96];
        for (n, e) in [
            (&even[..], &f4[..]),
            (&[0xc5; 96][..], &[1, 0, 0][..]),
            (&[0xc5; 96][..], &[1][..]),
            (&[0x03][..], &[3][..]),
            (&[][..], &f4[..]),
        ] {
            assert!(matches!(rsa_spki(n, e), Err(KmError::Conflict(_))), "{n:02x?} {e:02x?}");
        }
    }

    #[test]
    fn hmac_commitment_label_is_unchanged() {
        let obj = ObjectCfg { value_len: Some(32), ..cfg("CKO_SECRET_KEY", "CKK_GENERIC_SECRET") };
        assert_eq!(
            Commit::Hmac(HmacHash::Sha256).label(DEFAULT_COMMITMENT_LABEL, &obj),
            b"key-management/v1/commitment/CKK_GENERIC_SECRET/256"
        );
        assert_eq!(Commit::KcvEcb(BlockCipher::Aes).input(DEFAULT_COMMITMENT_LABEL, &obj).len(), 16);
        assert_eq!(Commit::KcvEcb(BlockCipher::Des3).input(DEFAULT_COMMITMENT_LABEL, &obj).len(), 8);
        assert_eq!(Commit::Kw.input(DEFAULT_COMMITMENT_LABEL, &obj).len(), 32);
    }

    /// Checks the usage attribute of each commitment (docs/DESIGN.md §3.1), and the cipher that
    /// each block cipher key type determines.
    #[test]
    fn commit_usage_bits_and_block_ciphers() {
        use BlockCipher::{Aes, Des3};
        let usage: Vec<_> = [
            Commit::Hmac(HmacHash::Sha256),
            Commit::Cmac,
            Commit::KcvEcb(Des3),
            Commit::KcvEcbDecrypt(Aes),
            Commit::Kw,
        ]
        .map(Commit::usage)
        .into();
        assert_eq!(usage, ["CKA_SIGN", "CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"]);
        let ciphers: Vec<_> =
            KeyType::ALL.iter().filter_map(|k| Some((*k, BlockCipher::for_key_type(*k)?.block_len()))).collect();
        assert_eq!(ciphers, [(KeyType::Aes, 16), (KeyType::Des3, 8)]);
    }

    #[test]
    fn curve_params_roundtrip_and_match_the_crates() {
        use p256::elliptic_curve::pkcs8::AssociatedOid;
        let oid = |o: pkcs8::ObjectIdentifier| o.to_der().unwrap();
        assert_eq!(Curve::P256.params(), oid(p256::NistP256::OID));
        assert_eq!(Curve::P384.params(), oid(p384::NistP384::OID));
        assert_eq!(Curve::P521.params(), oid(p521::NistP521::OID));
        assert_eq!(Curve::Secp256k1.params(), oid(k256::Secp256k1::OID));
        assert_eq!(Curve::BrainpoolP256r1.params(), oid(bp256::BrainpoolP256r1::OID));
        assert_eq!(Curve::BrainpoolP384r1.params(), oid(bp384::BrainpoolP384r1::OID));
        assert_eq!(Curve::Ed25519.params(), oid(ed25519_dalek::pkcs8::ALGORITHM_OID));
        assert_eq!(Curve::Ed448.params(), oid(ed448::pkcs8::ALGORITHM_OID));
        for c in Curve::ALL {
            assert_eq!(Curve::from_params(c.params()), Some(c));
        }
        assert_eq!(Curve::from_params(b"\x13\x0cedwards25519"), Some(Curve::Ed25519));
    }

    /// Core's curves are the `in_core` curves of the names table, in the table's order. A curve
    /// that is added to only one of the two fails here until the other one has it too. keys.toml
    /// accepts each curve by its canonical name and by its display name, as the lock and the
    /// messages write them.
    #[test]
    fn the_curves_are_the_names_tables() {
        let core: Vec<cakeys_names::Curve> = Curve::ALL.map(Curve::named).into();
        let table: Vec<cakeys_names::Curve> = cakeys_names::Curve::ALL.into_iter().filter(|c| c.in_core()).collect();
        assert_eq!(core, table);
        for c in Curve::ALL {
            let kt = if c.edwards() { KeyType::EcEdwards } else { KeyType::Ec };
            assert_eq!((Curve::from_cfg(kt, c.name()), Curve::from_cfg(kt, c.display())), (Some(c), Some(c)), "{c:?}");
            let other = if c.edwards() { KeyType::Ec } else { KeyType::EcEdwards };
            assert_eq!(Curve::from_cfg(other, c.name()), None, "{c:?}");
        }
        assert_eq!(Curve::from_cfg(KeyType::Ec, "prime256v1"), Some(Curve::P256));
        assert_eq!(Curve::from_cfg(KeyType::Ec, "curve25519"), None, "no Montgomery key type in core");
    }

    /// Every commitment is a kind in the names table, every kind belongs to a commitment, and
    /// every kind other than an HMAC has the name of its scheme (which must not change:
    /// `scheme_definitions_are_pinned`). So a `commit.*` row, the lock's scheme and the requested
    /// mechanism all refer to the same commitment.
    #[test]
    fn every_commitment_is_a_kind_of_the_names_table() {
        let ciphers = [BlockCipher::Aes, BlockCipher::Des3];
        let hashes = [HmacHash::Sha1, HmacHash::Sha224, HmacHash::Sha256, HmacHash::Sha384, HmacHash::Sha512];
        let all: Vec<Commit> = [Commit::Cmac, Commit::Kw]
            .into_iter()
            .chain(ciphers.into_iter().flat_map(|c| [Commit::KcvEcb(c), Commit::KcvEcbDecrypt(c)]))
            .chain(hashes.map(Commit::Hmac))
            .collect();
        for c in &all {
            assert_eq!(c.profile_kind(), c.kind().name(), "{c:?}");
            if !matches!(c, Commit::Hmac(_)) {
                assert_eq!(c.kind().name(), c.scheme().name(), "{c:?}");
            }
        }
        for kind in cakeys_names::CommitKind::ALL {
            assert!(all.iter().any(|c| c.kind() == kind), "{kind:?} is no commitment's kind");
        }
        for c in ciphers {
            assert_eq!(BlockCipher::for_key_type(c.key_type()), Some(c), "{c:?}");
            assert!(Commit::KcvEcb(c).mechanism().ends_with("_ECB"), "{c:?}");
        }
        assert_ne!(Commit::KcvEcb(BlockCipher::Aes).mechanism(), Commit::KcvEcb(BlockCipher::Des3).mechanism());
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
                    migrate: crate::config::SpecMigrateCfg::default(),
                    tokens: BTreeMap::new(),
                };
                spec_digest(&o, &s)
            };
        // The certificate type is in `certificateType`. This digest changed when the field was
        // introduced and is pinned since then. The RSA, EC and generic-secret digests below must
        // not change.
        let cert = ObjectCfg { certificate_type: Some("CKC_X_509".into()), ..cfg("CKO_CERTIFICATE", "") };
        let none = SpecCfg {
            object: "x".into(),
            attributes: BTreeMap::new(),
            public_attributes: BTreeMap::new(),
            migrate: crate::config::SpecMigrateCfg::default(),
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

    /// Known-answer tests that pin the definition of each scheme. A change of the code or of a
    /// crate that alters any of these values breaks existing locks, so it must fail here and not
    /// in a user's lock. A scheme whose computation changes needs a new name (docs/DESIGN.md §10).
    #[test]
    fn scheme_definitions_are_pinned() {
        let obj = |kt: &str, len: u64| ObjectCfg { value_len: Some(len), ..cfg("CKO_SECRET_KEY", kt) };
        // The input that each commitment scheme gives to the token. The token's output is then
        // hashed.
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
            ("CKK_AES", 32, Commit::KcvEcb(BlockCipher::Aes), "sha256-L1W0lzlDj7Pcu44tnVa/ekyQRHsIybF5gUIsG/oi270="),
            (
                "CKK_AES",
                16,
                Commit::KcvEcbDecrypt(BlockCipher::Aes),
                "sha256-Ht1do336beKCgXkt86UdPfbUUdqLPc7Md3/3IybSftI=",
            ),
            ("CKK_AES", 32, Commit::Kw, "sha256-woiHkSVHlbF2VQCQbiHKffrxo2ShyBOMzsdtKDPtH7c="),
            // DES3 uses the same construction, with one 8-byte block, which is the length that
            // the key type fixes.
            ("CKK_DES3", 24, Commit::KcvEcb(BlockCipher::Des3), "sha256-NRjuYQG3VCPqI2KhH8s3pChrlFGSWwvCQNd4BedHPeo="),
            (
                "CKK_DES3",
                24,
                Commit::KcvEcbDecrypt(BlockCipher::Des3),
                "sha256-KBjM0G2T/K2ydJyVcszuEEdo6aKfui1mkr+32V5AcfQ=",
            ),
        ] {
            assert_eq!(sri(&c.input(DEFAULT_COMMITMENT_LABEL, &obj(kt, len))), want, "{kt} {}", c.scheme());
        }
        // rfc7093m4: the canonical SPKI from fixed points (a compressed secp256k1 point is
        // normalized to the uncompressed form).
        let unhex = |h: &str| crate::hex::decode(h).unwrap();
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

    /// The list of deprecated schemes (docs/DESIGN.md §3.1, finding S15) is empty today, so the
    /// addition of a name must be a deliberate change that a person reviews. A deprecated name
    /// must be a scheme that this cakeys knows.
    #[test]
    fn the_deprecation_register_is_pinned() {
        assert!(Scheme::DEPRECATED.is_empty(), "deprecating a scheme is a design decision; see docs/DESIGN.md §3.1");
    }

    /// Scheme names are keys in the lock, so a renamed scheme breaks every lock that records it
    /// (§10).
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

    /// Pins the canonical input of each attestation scheme (docs/DESIGN.md §3.7, §10). The
    /// attestations are verified evidence: the Yubico PIV certificate chain, and `TPM2_Certify`
    /// over the object's Name. An ID is the SHA-256 of the canonical encoding below, so a change
    /// here breaks locks and must use a new scheme name instead.
    #[test]
    fn attestation_definitions_are_pinned() {
        let kinds: Vec<(&str, &str)> =
            Scheme::ALL.into_iter().filter_map(|s| Some((s.name(), s.attestation_kind()?))).collect();
        assert_eq!(kinds, [("piv-attestation", "yubico-piv"), ("tpm-certify", "tpm-certify")]);
        // piv-attestation: the domain tag, then the issuer SPKI (the f9 device key), the subject
        // SPKI (the key), the firmware (1.3.6.1.4.1.41482.3.3), the serial number (.3.7), the PIN
        // and touch policy (.3.8) and the form factor (.3.9). Each field has a length prefix, in
        // that order, and an absent extension is an empty field.
        assert_eq!(
            piv_attestation_id(b"issuer", b"subject", b"\x05\x07\x04", b"\x00\x01\x02\x03", b"\x04\x01", b"\x05"),
            "sha256-Ag0O41w4o5kTLdmBZotdL9DKXHQKn36fPRTUWXLpTJY="
        );
        // tpm-certify: the domain tag, then the attested Name (the nameAlg tag followed by
        // H(TPMT_PUBLIC)) and the qualified Name. The nonce that proves freshness is used only
        // during verification and is never part of the ID.
        assert_eq!(
            tpm_certify_id(b"\x00\x0bname", b"\x00\x0bqn"),
            "sha256-gtESMfaa12qwnzF1o9xnvKzbZUFlO7WOTHi4aj52aq0="
        );
    }

    /// Checks the curve that an SPKI names, which the stand-in check compares with the private
    /// key's own curve.
    #[test]
    fn spki_curve_names_the_key_kind() {
        macro_rules! fixture {
            ($f:literal) => {
                include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/", $f))
            };
        }
        let curve = |cert: &[u8]| KeyAlg::of_spki(&cert_spki(cert).unwrap()).unwrap().curve();
        assert_eq!(curve(fixture!("tpm-import-rsa2048-cert.der")), None);
        assert_eq!(curve(fixture!("tpm-import-p256-cert.der")), Some(Curve::P256));
        assert_eq!(curve(fixture!("adopt-cert-p384.der")), Some(Curve::P384));
        assert_eq!(curve(fixture!("adopt-cert-ed25519.der")), Some(Curve::Ed25519));
    }

    /// Review D6 removed a second dispatcher, which read some SPKI forms that `KeyAlg::of_spki`
    /// does not read. Both `KeyAlg::of_spki` and `spki_canonical` refuse each of those forms.
    /// Every SPKI that a caller passes has gone through `spki_canonical`, so one dispatcher
    /// decides both.
    #[test]
    fn spki_curve_reads_what_canonical_spkis_hold() {
        let tlv = |tag: u8, body: &[&[u8]]| {
            let body = body.concat();
            [&[tag, u8::try_from(body.len()).unwrap()][..], &body].concat()
        };
        let ec_public_key = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let ed25519 = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let secp384r1 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        let spki = |alg: &[&[u8]], point: &[u8]| tlv(0x30, &[&tlv(0x30, alg), &tlv(0x03, &[&[0], point])]);
        let cases: [(&str, Vec<u8>); 4] = [
            ("an Edwards curve's OID under id-ecPublicKey", spki(&[&ec_public_key, &ed25519], &[7; 32])),
            (
                "an Edwards curve by name under id-ecPublicKey",
                spki(&[&ec_public_key, &tlv(0x13, &[b"edwards25519"])], &[7; 32]),
            ),
            ("a Weierstrass curve's OID as the algorithm", spki(&[&secp384r1], &[&[4][..], &[7; 96]].concat())),
            ("no SubjectPublicKeyInfo", b"\x30\x00".to_vec()),
        ];
        for (what, der) in cases {
            assert!(
                matches!(KeyAlg::of_spki(&der), Err(KmError::Unsupported(_))),
                "{what}: {:?}",
                KeyAlg::of_spki(&der)
            );
            assert!(matches!(spki_canonical(&der), Err(KmError::Unsupported(_))), "{what}");
        }
    }
}
