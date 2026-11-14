//! Proof of possession (docs/DESIGN.md §3.6): the token proves it holds the private key that
//! belongs to the public key the identity hashes — by signing, by deriving (ECDH), or by
//! decrypting (RSA-OAEP) a fresh, domain-separated challenge — and the host checks the result
//! against the same canonical SPKI that `rfc7093m4` hashes. This binds a private-key object to
//! its identity even when the public key comes from a separate public-key object (H1 in
//! docs/REVIEW-2026-11-11.md).
//!
//! Verification uses the `RustCrypto` crates; no proof value is ever stored.

use crate::error::{KmError, Result};
use crate::sig;
pub use crate::sig::EcdsaHash;
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{Generate, PublicKey, ecdh::EphemeralSecret};
use hmac::{Hmac, KeyInit, Mac};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain separator: the challenge is never a valid encoding of anything else a key signs
/// (certificates, CMS, SSH, ...), since none of those start with this ASCII text.
pub const DOMAIN: &[u8] = b"cakeys/pop/v1\0";

/// `DOMAIN ‖ SHA-256(spki) ‖ nonce`.
#[must_use]
pub fn message(spki: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, Sha256::digest(spki).as_slice(), nonce].concat()
}

/// A challenge with a fresh 32-byte nonce from the OS.
///
/// # Errors
///
/// `Unavailable` if the OS random number generator fails.
pub fn challenge(spki: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}")))?;
    Ok(message(spki, &nonce))
}

/// Verify `sig` over `msg` with the key in `spki`, as the token produced it (`crate::sig`):
/// - ECDSA: raw `r ‖ s` (PKCS#11) over the curve's hash of `msg` (`EcdsaHash::for_curve`);
/// - Ed25519: pure `EdDSA` over `msg`;
/// - RSA: PKCS#1 v1.5 with SHA-256 over `msg`.
///
/// # Errors
///
/// `Conflict` when the signature does not verify: the private key is not the one the identity
/// names. `Unsupported` for an Ed448 key (no verifier yet: opt in with
/// `binding = "token-asserted"`) or a key that is none of the three above.
pub fn verify(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let verdict = sig::ecdsa(spki, msg, sig, sig::Encoding::Raw, None)
        .or_else(|| sig::ed25519(spki, msg, sig))
        .or_else(|| sig::rsa_pkcs1v15::<Sha256>(spki, msg, sig));
    match verdict {
        Some(v) => v.map_err(|e| {
            KmError::Conflict(format!(
                "proof of possession failed: the private key did not sign for the public key {} ({e})",
                crate::id::sri(spki)
            ))
        }),
        None if ed448::pkcs8::PublicKeyBytes::from_public_key_der(spki).is_ok() => Err(KmError::Unsupported(
            "no Ed448 signature verifier to prove possession with; opt in with binding = \"token-asserted\"".into(),
        )),
        None => Err(KmError::Unsupported(format!(
            "proof of possession for the public key {}: not an ECDSA, Ed25519 or RSA key",
            crate::id::sri(spki)
        ))),
    }
}

/// The host side of a `pop-ecdh` proof: an ephemeral key on `curve`, the shared secret derived
/// against the public key in `spki`, and the MAC of `msg` the token must reproduce.
pub struct EcdhChallenge {
    /// The ephemeral public point, SEC1 uncompressed, for the token's `C_DeriveKey`.
    pub peer: Vec<u8>,
    /// HMAC-SHA256 over `msg` keyed with the shared secret.
    pub mac: Vec<u8>,
    /// The shared secret itself, for a token that derives only into an extractable secret
    /// (ykcs11 [src]): the token's derived value is compared with it instead of a MAC. Secret
    /// only to the two ephemeral parties, and used once.
    pub secret: Vec<u8>,
}

/// Start a `pop-ecdh` proof of possession: generate an ephemeral key on the curve of the public
/// key in `spki` and MAC `msg` with the shared secret it and the private half of `spki` would
/// derive. The token derives the same secret with `CKM_ECDH1_DERIVE` and `peer`, and MACs the same
/// `msg`; the MACs match only if the token's private key is the one `spki` names.
///
/// # Errors
///
/// `Unsupported` if the key's curve has no `RustCrypto` ECDH; `Unavailable` if the OS random
/// number generator fails.
pub fn ecdh_challenge(spki: &[u8], msg: &[u8]) -> Result<EcdhChallenge> {
    let mut rng = getrandom::SysRng;
    macro_rules! ecdh {
        ($curve:ty) => {
            if let Ok(pk) = PublicKey::<$curve>::from_public_key_der(spki) {
                let eph = EphemeralSecret::<$curve>::try_generate_from_rng(&mut rng)
                    .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}")))?;
                let shared = eph.diffie_hellman(&pk);
                return Ok(EcdhChallenge {
                    peer: eph.public_key().to_sec1_point(false).as_bytes().to_vec(),
                    mac: mac_sha256(shared.raw_secret_bytes(), msg),
                    secret: shared.raw_secret_bytes().to_vec(),
                });
            }
        };
    }
    ecdh!(p256::NistP256);
    ecdh!(p384::NistP384);
    ecdh!(p521::NistP521);
    ecdh!(k256::Secp256k1);
    ecdh!(bp256::BrainpoolP256r1);
    ecdh!(bp384::BrainpoolP384r1);
    Err(KmError::Unsupported(format!("no RustCrypto ECDH for the public key {}", crate::id::sri(spki))))
}

/// Start a `pop-decrypt` proof of possession: `msg` encrypted to the public key in `spki` with
/// RSA-OAEP (SHA-1, MGF1-SHA1, empty label — the PKCS#11 baseline `SoftHSM` implements). Only the
/// matching private key decrypts it back to `msg`, which the token does with `CKM_RSA_PKCS_OAEP`.
///
/// # Errors
///
/// `Unsupported` if `spki` is not an RSA key; `Unavailable` if the OS random number generator
/// or the encryption fails (for instance, `msg` is too long for the modulus).
pub fn oaep_challenge(spki: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    rsa_encrypt(spki, RsaPadding::Oaep(OaepHash::Sha1), msg)
}

/// The RSA-OAEP hash, with MGF1 of the same hash: a transport wrap's and an OAEP proof's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OaepHash {
    Sha1,
    Sha256,
}

/// The RSA encryption paddings the probe tries a module's `C_Decrypt` with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 (`CKM_RSA_PKCS`).
    Pkcs1v15,
    /// OAEP with MGF1 of the same hash and an empty label (`CKM_RSA_PKCS_OAEP`).
    Oaep(OaepHash),
}

/// `msg` encrypted to the RSA public key in `spki` with `padding`.
///
/// # Errors
///
/// `Unsupported` if `spki` is not an RSA key; `Unavailable` if the OS random number generator
/// or the encryption fails (for instance, `msg` is too long for the modulus).
pub fn rsa_encrypt(spki: &[u8], padding: RsaPadding, msg: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("RSA encryption to this SPKI: {e}")))?;
    let rng = &mut getrandom::SysRng;
    match padding {
        RsaPadding::Pkcs1v15 => key.encrypt(rng, rsa::Pkcs1v15Encrypt, msg),
        RsaPadding::Oaep(OaepHash::Sha1) => key.encrypt(rng, rsa::Oaep::<sha1::Sha1>::new(), msg),
        RsaPadding::Oaep(OaepHash::Sha256) => key.encrypt(rng, rsa::Oaep::<Sha256>::new(), msg),
    }
    .map_err(|e| KmError::Unavailable(format!("RSA encryption: {e}")))
}

/// HMAC-SHA256 over `msg` keyed with `key`; HMAC takes any key length.
fn mac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time equality of a proof's expected and actual value; only the length is
/// observable. `subtle`'s (already a transitive `RustCrypto` dependency), not a hand-rolled XOR
/// fold the optimizer could turn into an early exit.
#[must_use]
pub fn ct_eq(expected: &[u8], got: &[u8]) -> bool {
    bool::from(expected.ct_eq(got))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout_is_pinned() {
        let m = message(b"spki", &[7u8; 32]);
        assert_eq!(&m[..14], b"cakeys/pop/v1\0");
        assert_eq!(&m[14..46], Sha256::digest(b"spki").as_slice());
        assert_eq!(&m[46..], &[7u8; 32]);
    }

    #[test]
    fn challenges_are_fresh() {
        assert_ne!(challenge(b"k").unwrap(), challenge(b"k").unwrap());
    }

    #[test]
    fn a_signature_by_another_key_is_a_conflict() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use p256::pkcs8::EncodePublicKey;
        let k1 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let k2 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let spki = k1.verifying_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let digest = EcdsaHash::Sha256.digest(&msg);
        let good: Signature = k1.sign_prehash(&digest).unwrap();
        let other: Signature = k2.sign_prehash(&digest).unwrap();
        verify(spki.as_bytes(), &msg, &good.to_bytes()).unwrap();
        assert!(matches!(verify(spki.as_bytes(), &msg, &other.to_bytes()), Err(KmError::Conflict(_))));
    }

    #[test]
    fn the_ecdh_mac_matches_on_both_sides() {
        use p256::elliptic_curve::{NonZeroScalar, ecdh::diffie_hellman};
        use p256::pkcs8::EncodePublicKey;
        // The token side, played on the host: derive with the private key and the challenge's
        // ephemeral point; the MACs must agree.
        let k = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let scalar = NonZeroScalar::<p256::NistP256>::from_repr([7u8; 32].into()).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let ch = ecdh_challenge(spki.as_bytes(), &msg).unwrap();
        let peer = p256::elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(&ch.peer).unwrap();
        let shared = diffie_hellman(scalar, peer.as_affine());
        assert_eq!(mac_sha256(shared.raw_secret_bytes(), &msg), ch.mac);
        assert!(ct_eq(&ch.mac, &ch.mac.clone()));
        let flipped: Vec<u8> = ch.mac.iter().copied().rev().collect();
        assert!(!ct_eq(&ch.mac, &flipped));
    }

    #[test]
    fn ecdh_needs_a_supported_curve() {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        // Edwards keys have no RustCrypto ECDH here: refused, not silently misproven.
        let spki = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_public_key_der().unwrap();
        assert!(matches!(ecdh_challenge(spki.as_bytes(), b"m"), Err(KmError::Unsupported(_))));
    }
}
