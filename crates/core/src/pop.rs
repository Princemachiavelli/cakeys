//! Proof of possession (docs/DESIGN.md §3.6): the token signs a fresh, domain-separated challenge
//! with the private key, and the host verifies the signature against the same canonical SPKI that
//! `rfc7093m4` hashes. This binds a private-key object to its identity even when the public key
//! comes from a separate public-key object (H1 in docs/REVIEW-2026-11-11.md).
//!
//! Verification uses the RustCrypto crates; the signature itself is never stored.

use crate::error::{KmError, Result};
use crate::id::Curve;
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Domain separator: the challenge is never a valid encoding of anything else a key signs
/// (certificates, CMS, SSH, ...), since none of those start with this ASCII text.
pub const DOMAIN: &[u8] = b"cakeys/pop/v1\0";

/// `DOMAIN ‖ SHA-256(spki) ‖ nonce`.
pub fn message(spki: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, Sha256::digest(spki).as_slice(), nonce].concat()
}

/// A challenge with a fresh 32-byte nonce from the OS.
pub fn challenge(spki: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}")))?;
    Ok(message(spki, &nonce))
}

/// Hash for ECDSA on each Weierstrass curve: the one matching its strength (FIPS 186-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaHash {
    Sha256,
    Sha384,
    Sha512,
}

impl EcdsaHash {
    pub fn for_curve(curve: Curve) -> Option<EcdsaHash> {
        match curve {
            Curve::P256 | Curve::Secp256k1 | Curve::BrainpoolP256r1 => Some(EcdsaHash::Sha256),
            Curve::P384 | Curve::BrainpoolP384r1 => Some(EcdsaHash::Sha384),
            Curve::P521 => Some(EcdsaHash::Sha512),
            Curve::Ed25519 | Curve::Ed448 => None,
        }
    }

    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            EcdsaHash::Sha256 => Sha256::digest(msg).to_vec(),
            EcdsaHash::Sha384 => Sha384::digest(msg).to_vec(),
            EcdsaHash::Sha512 => Sha512::digest(msg).to_vec(),
        }
    }
}

/// Verify `sig` over `msg` with the key in `spki`, as the token produced it:
/// - ECDSA: raw `r ‖ s` (PKCS#11) over the curve's hash of `msg` (`EcdsaHash::for_curve`);
/// - Ed25519: pure EdDSA over `msg`;
/// - RSA: PKCS#1 v1.5 with SHA-256 over `msg`.
///
/// A signature that does not verify is a `Conflict`: the private key is not the one the
/// identity names. Ed448 has no verifier yet (`Unsupported`).
pub fn verify(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let bad = |e: &dyn std::fmt::Display| {
        KmError::Conflict(format!(
            "proof of possession failed: the private key did not sign for the public key {} ({e})",
            crate::id::sri(spki)
        ))
    };
    macro_rules! ecdsa {
        ($curve:ty, $hash:expr) => {
            if let Ok(k) = p256::elliptic_curve::PublicKey::<$curve>::from_public_key_der(spki) {
                // Either s is valid ECDSA; secp256k1's verifier insists on the low one.
                let sig = ecdsa::Signature::<$curve>::from_slice(sig).map_err(|e| bad(&e))?.normalize_s();
                return ecdsa::VerifyingKey::<$curve>::from(k)
                    .verify_prehash(&$hash.digest(msg), &sig)
                    .map_err(|e| bad(&e));
            }
        };
    }
    ecdsa!(p256::NistP256, EcdsaHash::Sha256);
    ecdsa!(p384::NistP384, EcdsaHash::Sha384);
    ecdsa!(p521::NistP521, EcdsaHash::Sha512);
    ecdsa!(k256::Secp256k1, EcdsaHash::Sha256);
    ecdsa!(bp256::BrainpoolP256r1, EcdsaHash::Sha256);
    ecdsa!(bp384::BrainpoolP384r1, EcdsaHash::Sha384);
    if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_der(spki) {
        let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|e| bad(&e))?;
        return k.verify_strict(msg, &sig).map_err(|e| bad(&e));
    }
    if ed448::pkcs8::PublicKeyBytes::from_public_key_der(spki).is_ok() {
        return Err(KmError::Unsupported(
            "no Ed448 signature verifier to prove possession with; opt in with binding = \"token-asserted\"".into(),
        ));
    }
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("proof of possession for this SPKI: {e}")))?;
    let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| bad(&e))?;
    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(msg, &sig).map_err(|e| bad(&e))
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
        use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
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
}
