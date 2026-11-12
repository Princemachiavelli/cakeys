//! Proof of possession (docs/DESIGN.md §3.6): the token proves it holds the private key that
//! belongs to the public key the identity hashes — by signing, by deriving (ECDH), or by
//! decrypting (RSA-OAEP) a fresh, domain-separated challenge — and the host checks the result
//! against the same canonical SPKI that `rfc7093m4` hashes. This binds a private-key object to
//! its identity even when the public key comes from a separate public-key object (H1 in
//! docs/REVIEW-2026-11-11.md).
//!
//! Verification uses the RustCrypto crates; no proof value is ever stored.

use crate::error::{KmError, Result};
use crate::id::Curve;
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::signature::Verifier;
use hmac::{Hmac, KeyInit, Mac};
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{ecdh::EphemeralSecret, Generate, PublicKey};
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

/// The host side of a `pop-ecdh` proof: an ephemeral key on `curve`, the shared secret derived
/// against the public key in `spki`, and the MAC of `msg` the token must reproduce.
pub struct EcdhChallenge {
    /// The ephemeral public point, SEC1 uncompressed, for the token's `C_DeriveKey`.
    pub peer: Vec<u8>,
    /// HMAC-SHA256 over `msg` keyed with the shared secret.
    pub mac: Vec<u8>,
}

/// Start a `pop-ecdh` proof of possession: generate an ephemeral key on the curve of the public
/// key in `spki` and MAC `msg` with the shared secret it and the private half of `spki` would
/// derive. The token derives the same secret with `CKM_ECDH1_DERIVE` and `peer`, and MACs the same
/// `msg`; the MACs match only if the token's private key is the one `spki` names.
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
    Err(KmError::Unsupported(format!(
        "no RustCrypto ECDH for the public key {}",
        crate::id::sri(spki)
    )))
}

/// Start a `pop-decrypt` proof of possession: `msg` encrypted to the public key in `spki` with
/// RSA-OAEP (SHA-1, MGF1-SHA1, empty label — the PKCS#11 baseline SoftHSM implements). Only the
/// matching private key decrypts it back to `msg`, which the token does with `CKM_RSA_PKCS_OAEP`.
pub fn oaep_challenge(spki: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("proof of possession for this SPKI: {e}")))?;
    key.encrypt(&mut getrandom::SysRng, rsa::Oaep::<sha1::Sha1>::new(), msg)
        .map_err(|e| KmError::Unavailable(format!("RSA-OAEP challenge: {e}")))
}

/// HMAC-SHA256 over `msg` keyed with `key`; HMAC takes any key length.
fn mac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time equality of a proof's expected and actual value; only the length is observable.
pub fn ct_eq(expected: &[u8], got: &[u8]) -> bool {
    expected.len() == got.len()
        && expected.iter().zip(got).fold(0u8, |diff, (a, b)| diff | a ^ b) == 0
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

    #[test]
    fn the_ecdh_mac_matches_on_both_sides() {
        use p256::elliptic_curve::{ecdh::diffie_hellman, NonZeroScalar};
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
        let spki = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_public_key_der()
            .unwrap();
        assert!(matches!(
            ecdh_challenge(spki.as_bytes(), b"m"),
            Err(KmError::Unsupported(_))
        ));
    }
}
