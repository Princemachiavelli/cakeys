//! CA-ID computation: SRI rendering, spec digest, SPKI normalisation, commitment labels.
//!
//! Public keys are decoded and re-encoded by the `RustCrypto` crates (`p256`, `p384`, `p521`,
//! `ed25519-dalek`, `ed448`, `rsa`); this module only chooses which one by curve or OID.

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

/// `sha256-<base64>`: drops straight into a Nix `outputHash`, but nothing depends on it.
#[must_use]
pub fn sri(bytes: &[u8]) -> String {
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes)))
}

/// Whether `s` is an SRI SHA-256 digest as `sri` writes it: `sha256-` and 32 bytes in padded
/// standard base64.
#[must_use]
pub fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .is_some_and(|d| d.len() == 32)
}

/// Hash of the canonical JSON (RFC 8785, JCS) of (object type, policy attributes, public-half
/// attributes).
///
/// # Panics
///
/// Never: the document holds only strings, booleans and small integers, which always canonicalize.
#[must_use]
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
    // RFC 8785 (JCS): keys sorted at every level, no whitespace. The document holds only
    // strings, booleans and small integers, which every JSON library serializes alike.
    sri(serde_jcs::to_string(&doc).expect("a JSON value of strings, booleans and integers canonicalizes").as_bytes())
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
    /// RFC 7093 §2 method 4: SHA-256 of the canonical `SubjectPublicKeyInfo`.
    Rfc7093m4,
    /// SHA-256 of a certificate's DER.
    Certhash,
    /// SHA-256 of a data object's `CKA_VALUE` (of a private one only when its spec declares
    /// `CKA_PRIVATE = true`: docs/DESIGN.md §8.2).
    Valuehash,
    /// HMAC over the commitment label (`Commit::Hmac`).
    Commitment,
    /// AES-CMAC over the commitment label (`Commit::Cmac`).
    Cmac,
    /// ECB encryption (AES, DES3) of one block derived from the label: a key check value
    /// (`Commit::KcvEcb`).
    KcvEcb,
    /// ECB decryption of that block, for decrypt-only keys (`Commit::KcvEcbDecrypt`).
    KcvEcbDec,
    /// RFC 3394 key wrap of a fixed key derived from the label (`Commit::Kw`).
    Kw,
    /// A `YubiKey` PIV attestation, verified to the pinned Yubico root (per realisation).
    PivAttestation,
    /// A native `TPM2_Certify`, verified against a provisioned Attestation Key (per realisation).
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

    /// Schemes whose computation is deprecated (docs/DESIGN.md §3.1). Identities already locked
    /// under one keep verifying — with a warning — but `lock` never records a new one: a
    /// changed or weakened computation gets a *new* scheme name (§10), so the empty list is the
    /// "nothing is deprecated" state, pinned by test.
    pub const DEPRECATED: [Scheme; 0] = [];

    /// Input-only aliases (CLI and Nix library); a lock always uses the scheme name.
    pub const ALIASES: [(&str, Scheme); 1] = [("pubkeyhash", Scheme::Rfc7093m4)];

    /// The name the lock records.
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

    /// The scheme a lock names, exactly (no aliases: the lock refuses them).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The scheme a user names on input, resolving aliases.
    #[must_use]
    pub fn from_input(name: &str) -> Option<Scheme> {
        Scheme::ALIASES.iter().find(|(a, _)| *a == name).map(|(_, s)| *s).or_else(|| Scheme::from_name(name))
    }

    /// Computed from a commitment label (every `Commit` variant).
    #[must_use]
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
    #[must_use]
    pub fn is_attestation(self) -> bool {
        self.attestation_kind().is_some()
    }

    /// The lock-record `attestation.kind` of an attestation scheme (§3.7): which evidence
    /// produced the ID. One kind per scheme, pinned so a lock names its evidence exactly.
    #[must_use]
    pub fn attestation_kind(self) -> Option<&'static str> {
        match self {
            Scheme::PivAttestation => Some("yubico-piv"),
            Scheme::TpmCertify => Some("tpm-certify"),
            _ => None,
        }
    }

    /// The attestation scheme a lock-record kind names.
    #[must_use]
    pub fn from_attestation_kind(kind: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.attestation_kind() == Some(kind))
    }

    /// Listed in [`Scheme::DEPRECATED`]: verifies with a warning, never newly recorded.
    #[must_use]
    pub(crate) fn is_deprecated(self) -> bool {
        Scheme::DEPRECATED.contains(&self) || deprecated_in_test(self)
    }
}

/// Whether a unit test of this crate marked `scheme` deprecated on its own thread
/// (`DEPRECATED_IN_TEST`, which only the unit tests compile). [`Scheme::DEPRECATED`] is empty, so
/// without this mark no test could reach the rule that a deprecated scheme is never newly
/// recorded. Outside this crate's unit tests the function always returns false.
#[cfg(not(test))]
fn deprecated_in_test(_scheme: Scheme) -> bool {
    false
}

/// See the other definition of this function, which every build outside this crate's unit tests
/// uses.
#[cfg(test)]
fn deprecated_in_test(scheme: Scheme) -> bool {
    DEPRECATED_IN_TEST.with(|d| d.get() == Some(scheme))
}

#[cfg(test)]
thread_local! {
    /// The scheme that a unit test treats as deprecated on its own thread. Each test runs on its
    /// own thread, so a mark that one test sets does not reach another test.
    pub(crate) static DEPRECATED_IN_TEST: std::cell::Cell<Option<Scheme>> = const { std::cell::Cell::new(None) };
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The canonical encoding shared by the attestation commitment definitions: a domain-separated
/// tag, then each field as a u32 length prefix and its bytes, so no field can bleed into the
/// next (§3.7, §10).
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

/// The `piv-attestation` commitment (§3.7): what a `YubiKey` PIV attestation certificate *asserts*,
/// not its bytes. The certificate is generated on demand with a random serial and a randomized
/// ECDSA signature, so hashing the DER would be unstable; these fields are the stable claims.
/// `issuer_spki` is the device attestation key in slot f9 (pinned per realisation through the
/// verified chain to the Yubico root), `subject_spki` is the attested key — the same public key
/// the object's `rfc7093m4` hashes, which the caller must have checked — and the rest are the
/// Yubico extension values (1.3.6.1.4.1.41482.3.3/.3.7/.3.8/.3.9), empty when the cert omits one.
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

/// The `tpm-certify` commitment (§3.7): the Name and qualified Name a `TPM2_Certify` statement
/// attests, signed by an Attestation Key. The Name is `nameAlg ‖ H(TPMT_PUBLIC)` — it covers the
/// public key, every `objectAttributes` bit and the `authPolicy` — and the qualified Name places
/// the object in its hierarchy. The qualifying data (host nonce) proves freshness and is
/// verification evidence only: never part of the ID.
#[must_use]
pub fn tpm_certify_id(name: &[u8], qualified_name: &[u8]) -> String {
    sri(&attest_encoding(b"cakeys/tpm-certify/v1\0", &[name, qualified_name]))
}

/// Hash of an HMAC commitment. A key bound to a hash (`CKK_SHA384_HMAC`, ...) is committed with
/// that hash; generic secrets use SHA-256.
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
    /// The HMAC hash for a secret key type, if it is an HMAC-capable type.
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

/// The block cipher of a key check value (`Commit::KcvEcb`, `Commit::KcvEcbDecrypt`), which the
/// key type implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCipher {
    /// AES (`CKK_AES`, `CKM_AES_ECB`): 16-byte blocks.
    Aes,
    /// Three-key Triple DES (`CKK_DES3`, `CKM_DES3_ECB`): 8-byte blocks.
    Des3,
}

impl BlockCipher {
    /// The block cipher of a secret key type, if it is one.
    #[must_use]
    pub fn for_key_type(key_type: KeyType) -> Option<BlockCipher> {
        match key_type {
            KeyType::Aes => Some(BlockCipher::Aes),
            KeyType::Des3 => Some(BlockCipher::Des3),
            _ => None,
        }
    }

    /// The key type it is the cipher of.
    #[must_use]
    pub fn key_type(self) -> KeyType {
        match self {
            BlockCipher::Aes => KeyType::Aes,
            BlockCipher::Des3 => KeyType::Des3,
        }
    }

    /// The block length in bytes: what a key check value encrypts.
    #[must_use]
    pub fn block_len(self) -> usize {
        match self {
            BlockCipher::Aes => 16,
            BlockCipher::Des3 => 8,
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
    /// ECB encryption (`CKM_AES_ECB`, `CKM_DES3_ECB`) of one block, the first block-length bytes
    /// of SHA-256(label): a key check value (`CKA_ENCRYPT`). Single-block ECB only: a fixed nonce
    /// with CTR/GCM would leak. One scheme for both ciphers, as for the HMAC hashes: the key
    /// type is in the label. Not the payment industry's KCV (the key's encryption of a zero
    /// block): that block carries no label and no key type, HSMs hand it out freely, and the
    /// lock's hash of a whole block could not be compared with its printed three bytes anyway.
    KcvEcb(BlockCipher),
    /// ECB decryption of one such block (`CKA_DECRYPT`): for decrypt-only keys.
    KcvEcbDecrypt(BlockCipher),
    /// `CKM_AES_KEY_WRAP` (RFC 3394, deterministic) of a fixed key, SHA-256(label) (`CKA_WRAP`).
    Kw,
}

impl Commit {
    /// The scheme this commitment's ID is recorded under.
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

    /// The usage bit a spec declares to have this commitment computed (docs/DESIGN.md §3.1).
    #[must_use]
    pub fn usage(self) -> &'static str {
        match self {
            Commit::Hmac(_) | Commit::Cmac => "CKA_SIGN",
            Commit::KcvEcb(_) => "CKA_ENCRYPT",
            Commit::KcvEcbDecrypt(_) => "CKA_DECRYPT",
            Commit::Kw => "CKA_WRAP",
        }
    }

    /// The kind a profile's `commit.<kind>.<key type>.<bytes>` rows name it by
    /// (`cakeys_names::CommitKind`, whose table names it and the mechanism it runs): the
    /// scheme's own name, the HMAC's hash beside it (one scheme for every hash, which a generic
    /// secret does not imply). The cipher is the row's key type, as it is the label's.
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

    /// The `CKM_` name of the mechanism the commitment runs: what a declared
    /// `CKA_ALLOWED_MECHANISMS` must hold for it, what cakeys-pkcs11's `commit_mechanism` asks
    /// the token for, and what a `commit.*` row was measured with: [`Commit::kind`]'s, on a
    /// check value's cipher.
    #[must_use]
    pub fn mechanism(self) -> &'static str {
        let key_type = match self {
            Commit::KcvEcb(c) | Commit::KcvEcbDecrypt(c) => c.key_type().name(),
            // No cipher: the kind alone names the mechanism.
            Commit::Hmac(_) | Commit::Cmac | Commit::Kw => "",
        };
        self.kind().mechanism(key_type)
    }

    /// [`Commit::kind`]'s name: what a `commit.*` row calls it (review 2026-11-23 A-9: one
    /// table, no name of the profile's own).
    #[must_use]
    pub fn profile_kind(self) -> &'static str {
        self.kind().name()
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

    /// The fixed input the token operates on: the label, or its SHA-256 (truncated to one block
    /// of the cipher for the KCV).
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

/// Named curves for `CKK_EC` and `CKK_EC_EDWARDS`: the curves of `cakeys_names::Curve` that
/// core has a key type for (`in_core`), whose table gives each its names, parameters and ECDSA
/// hash. This enum holds what core computes with, so a curve it has no key type for (a
/// Montgomery one) cannot reach a key here.
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

/// Named curves tokens offer that have no `RustCrypto` crate to validate and encode them with.
pub const CURVES_WITHOUT_CRATE: [&str; 1] = ["brainpoolP512r1"];

/// The curve in the names table: what names it, and what its ECDSA hash is
/// (`HashAlg::for_curve` takes a core curve through this).
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
    /// Every curve cakeys has a key type for, Weierstrass then Edwards: the curves keys.toml
    /// takes, and the ones the probe generates on (beside the Montgomery curves it measures).
    /// The names table's `in_core` curves, in its order (`the_curves_are_the_names_tables`).
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

    /// The curve in the names table.
    #[must_use]
    pub fn named(self) -> cakeys_names::Curve {
        self.into()
    }

    /// `curve` in keys.toml, for the given `keyType`: the canonical name, the display name
    /// (`P-256`, `Ed25519`), or OpenSSL's `prime256v1`.
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

    /// The canonical `curve` name, as recorded in the lock.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.named().name()
    }

    /// An Edwards curve (`CKK_EC_EDWARDS`) rather than a Weierstrass one (`CKK_EC`).
    #[must_use]
    pub fn edwards(self) -> bool {
        self.named().family() == cakeys_names::Family::Edwards
    }

    /// `CKA_EC_PARAMS` used when generating: the DER OID (RFC 5480 / RFC 8410).
    #[must_use]
    pub fn params(self) -> &'static [u8] {
        self.named().params()
    }

    /// PKCS#11 3.0 also allows Edwards curves as a `PrintableString` curve name.
    #[must_use]
    pub fn params_by_name(self) -> Option<&'static [u8]> {
        self.named().params_by_name()
    }

    /// The curve named by a token's `CKA_EC_PARAMS`.
    #[must_use]
    pub fn from_params(params: &[u8]) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.params() == params || c.params_by_name() == Some(params))
    }

    /// The name a message gives it: `P-256`, `Ed25519`.
    #[must_use]
    pub fn display(self) -> &'static str {
        self.named().display()
    }
}

/// The size in bits of an RSA modulus (`cakeys_names::modulus_bits`): its significant bits, never
/// its bytes times eight.
pub use cakeys_names::modulus_bits;

/// What a key is, by its `AlgorithmIdentifier` (ISSUES.md Q20): a key on a curve (Edwards
/// included) or RSA. The one parser that reads it is chosen by these OIDs, never by trying each
/// in turn, so a malformed key is reported by the parser of its own type.
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
    /// The key a `SubjectPublicKeyInfo` holds.
    ///
    /// # Errors
    ///
    /// `Unsupported` for bytes that are no `SubjectPublicKeyInfo`, or a key of an algorithm or
    /// curve cakeys does not read.
    pub fn of_spki(spki: &[u8]) -> Result<KeyAlg> {
        KeyAlg::read_spki(spki).map(|(alg, _)| alg)
    }

    /// The curve: `Some` for an EC or Edwards key, `None` for RSA. With [`Self::of_spki`], the
    /// curve a canonical SPKI's key is on (review D6, and 2026-11-23 A-13).
    #[must_use]
    pub fn curve(self) -> Option<Curve> {
        match self {
            KeyAlg::Ec(c) => Some(c),
            KeyAlg::Rsa => None,
        }
    }

    /// [`KeyAlg::of_spki`], with the parsed SPKI its key's own parser takes next: the bytes
    /// are decoded once.
    pub(crate) fn read_spki(spki: &[u8]) -> Result<(KeyAlg, pkcs8::SubjectPublicKeyInfoRef<'_>)> {
        let info = pkcs8::SubjectPublicKeyInfoRef::from_der(spki)
            .map_err(|e| KmError::Unsupported(format!("not a SubjectPublicKeyInfo: {e}").into()))?;
        Ok((KeyAlg::of(&info.algorithm)?, info))
    }

    /// The key a PKCS#8 `PrivateKeyInfo` holds.
    ///
    /// # Errors
    ///
    /// As [`KeyAlg::of_spki`], for a `PrivateKeyInfo`.
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
        // An Edwards key's algorithm OID is its curve's (RFC 8410), what `Curve::params` holds.
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
/// `Unsupported` for no SPKI, one of a key type cakeys does not hash ([`KeyAlg::of_spki`]), or
/// one its algorithm's own parser refuses, which names the error.
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

/// The RSA public key a DER SPKI holds, whatever its size (`rsa_key`): for what reads a key
/// without computing with it (its identity, its modulus and exponent, its size). The `rsa`
/// crate's own parser refuses keys outside its limits.
///
/// # Errors
///
/// The reason, when it is not an SPKI holding an RSA key at all.
pub fn rsa_of_spki(spki: &[u8]) -> std::result::Result<rsa::PublicKey, String> {
    let info = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(spki).map_err(|e| e.to_string())?;
    let bits = info.subject_public_key.as_bytes().ok_or("the key's bits are not whole bytes")?;
    let key = rsa::pkcs1::RsaPublicKeyRef::from_der(bits).map_err(|e| e.to_string())?;
    rsa_key(key.modulus.as_bytes(), key.public_exponent.as_bytes()).map_err(str::to_owned)
}

/// Canonical DER SPKI from `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` (big-endian), of any size.
///
/// # Errors
///
/// `Conflict` if the values are not an RSA public key at all (`rsa_key`).
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    let key = rsa_key(modulus, exponent)
        .map_err(|e| KmError::Conflict(Reason::check(Check::PublicKeyType, format!("invalid RSA public key: {e}"))))?;
    encode(&key)
}

/// An RSA public key from its modulus and exponent (big-endian), whatever its size: identity
/// hashes public bytes and needs no key the `rsa` crate would compute with, so its limits
/// (1024–8192 bits, e ≤ 2^33−1) are not cakeys' (id.rs F1; a legacy RSA-768 key or an
/// RSA-16384 one has an identity). Refused only when it is no RSA key: an even (or zero)
/// modulus, an even exponent or one below 3, or an exponent not below the modulus.
fn rsa_key(modulus: &[u8], exponent: &[u8]) -> std::result::Result<rsa::PublicKey, &'static str> {
    // Big-endian: the last byte is the low one (and an empty value is zero, so even).
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

/// Canonical DER SPKI of a certificate's subject key: links a certificate to its key object.
///
/// # Errors
///
/// `Conflict` if the value is not a parsable X.509 certificate, or its subject key is one
/// `spki_canonical` refuses (also `Unsupported` in that case).
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

    /// A key's type comes from its OIDs (ISSUES.md Q20): a P-256 key whose point is off the
    /// curve is refused by P-256's parser, by name, where it used to fall through to RSA's; an
    /// algorithm cakeys does not read is named by its OID; every curve's key reads as itself.
    #[test]
    fn a_key_is_read_by_the_parser_its_oids_name() {
        let good = p256::SecretKey::from_slice(&[1u8; 32]).unwrap().public_key().to_public_key_der().unwrap();
        assert_eq!(KeyAlg::of_spki(good.as_bytes()).unwrap(), KeyAlg::Ec(Curve::P256));
        let mut off_curve = good.as_bytes().to_vec();
        *off_curve.last_mut().unwrap() ^= 1;
        let e = spki_canonical(&off_curve).unwrap_err();
        assert!(matches!(&e, KmError::Unsupported(m) if m.starts_with("SPKI of a P-256 key")), "{e}");
        // X25519 (1.3.101.110): a Montgomery key, which no identity scheme reads.
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
            migrate: crate::config::SpecMigrateCfg::default(),
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
            migrate: crate::config::SpecMigrateCfg::default(),
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

    /// Every RSA key has an identity, whatever its size or exponent (id.rs F1): from its
    /// modulus and from its SPKI alike, the same bytes `rsa`'s checked key encodes to where it
    /// takes one (so no identity changed), and only what is no RSA key at all is refused.
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
        // Leading zero bytes are no part of the key.
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

    /// Each commitment's usage bit (DESIGN §3.1), and the cipher each block key type implies.
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

    /// Core's curves are the names table's `in_core` ones, in its order: a curve the table
    /// gains for core, or core for the table, fails here until the other has it. keys.toml takes
    /// each by its canonical and its display name, as the lock and the messages write them.
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

    /// Every commitment is a kind of the names table, every kind is some commitment's, and a
    /// kind other than an HMAC is named as its scheme (frozen: `scheme_definitions_are_pinned`),
    /// so a `commit.*` row, the lock's scheme and the mechanism asked for are one commitment.
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
        // The certificate type lives in `certificateType` (this digest changed when it did, and
        // is pinned since: the RSA, EC and generic-secret digests below must not move).
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
            ("CKK_AES", 32, Commit::KcvEcb(BlockCipher::Aes), "sha256-L1W0lzlDj7Pcu44tnVa/ekyQRHsIybF5gUIsG/oi270="),
            (
                "CKK_AES",
                16,
                Commit::KcvEcbDecrypt(BlockCipher::Aes),
                "sha256-Ht1do336beKCgXkt86UdPfbUUdqLPc7Md3/3IybSftI=",
            ),
            ("CKK_AES", 32, Commit::Kw, "sha256-woiHkSVHlbF2VQCQbiHKffrxo2ShyBOMzsdtKDPtH7c="),
            // DES3: the same construction, one 8-byte block, the length the key type fixes.
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
        // rfc7093m4: canonical SPKI from fixed points (compressed secp256k1 input normalizes).
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

    /// The curve an SPKI names, as the stand-in check compares it with the private key's own.
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

    /// The SPKI forms the second dispatcher read and `KeyAlg::of_spki` does not (review D6, which
    /// removed it): each is refused by `KeyAlg::of_spki` and by `spki_canonical`, which every SPKI
    /// a caller passes came through, so one dispatcher decides both.
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
