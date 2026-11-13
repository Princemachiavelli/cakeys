//! Signature verification shared by every proof cakeys checks on the host: proof of possession
//! (`pop`), the YubiKey PIV attestation chain and the TPM Attestation Key's `TPM2_Certify`
//! signature. Each function answers `None` when the SPKI is not a key it verifies, so callers can
//! try the next algorithm; `Some(Err(why))` covers a malformed signature and one that does not
//! verify alike. Callers word their own errors.

use crate::id::Curve;
use ecdsa::signature::Verifier;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// `Some(Ok(()))` verified; `Some(Err(why))` not; `None` the key is of another kind.
pub type Verdict = Option<Result<(), String>>;

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

/// How an ECDSA signature is encoded: raw `r ‖ s` (PKCS#11, TPM) or DER (X.509).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Raw,
    Der,
}

/// ECDSA over `msg` with the key in `spki` (P-256/384/521, secp256k1, brainpoolP256r1/P384r1),
/// hashed with `hash`, or with the curve's own hash when `None`. Either `s` is accepted:
/// secp256k1's verifier insists on the low one, so it is normalized first.
pub fn ecdsa(spki: &[u8], msg: &[u8], sig: &[u8], encoding: Encoding, hash: Option<EcdsaHash>) -> Verdict {
    macro_rules! curve {
        ($curve:ty, $own:expr) => {
            if let Ok(k) = p256::elliptic_curve::PublicKey::<$curve>::from_public_key_der(spki) {
                let sig = match encoding {
                    Encoding::Raw => ecdsa::Signature::<$curve>::from_slice(sig),
                    Encoding::Der => ecdsa::Signature::<$curve>::from_der(sig),
                };
                let sig = match sig {
                    Ok(s) => s.normalize_s(),
                    Err(e) => return Some(Err(e.to_string())),
                };
                let digest = hash.unwrap_or($own).digest(msg);
                return Some(
                    ecdsa::VerifyingKey::<$curve>::from(k).verify_prehash(&digest, &sig).map_err(|e| e.to_string()),
                );
            }
        };
    }
    curve!(p256::NistP256, EcdsaHash::Sha256);
    curve!(p384::NistP384, EcdsaHash::Sha384);
    curve!(p521::NistP521, EcdsaHash::Sha512);
    curve!(k256::Secp256k1, EcdsaHash::Sha256);
    curve!(bp256::BrainpoolP256r1, EcdsaHash::Sha256);
    curve!(bp384::BrainpoolP384r1, EcdsaHash::Sha384);
    None
}

/// Pure Ed25519 over `msg` (strict verification).
pub fn ed25519(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict {
    let k = ed25519_dalek::VerifyingKey::from_public_key_der(spki).ok()?;
    Some(
        ed25519_dalek::Signature::from_slice(sig)
            .map_err(|e| e.to_string())
            .and_then(|s| k.verify_strict(msg, &s).map_err(|e| e.to_string())),
    )
}

/// RSA PKCS#1 v1.5 over `msg` with the digest `D`.
pub fn rsa_pkcs1v15<D>(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict
where
    D: Digest + sha2::digest::const_oid::AssociatedOid,
{
    let k = rsa::PublicKey::from_public_key_der(spki).ok()?;
    Some(
        rsa::pkcs1v15::Signature::try_from(sig)
            .map_err(|e| e.to_string())
            .and_then(|s| rsa::pkcs1v15::VerifyingKey::<D>::new(k).verify(msg, &s).map_err(|e| e.to_string())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One P-256 key signs the same message as raw `r ‖ s` and as DER: both verify, a flipped
    /// message does not, and a key of another kind answers `None`.
    #[test]
    fn ecdsa_encodings_and_kinds() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use p256::pkcs8::EncodePublicKey;
        let k = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        let s: Signature = k.sign_prehash(&EcdsaHash::Sha384.digest(b"m")).unwrap();
        assert_eq!(ecdsa(spki.as_bytes(), b"m", &s.to_bytes(), Encoding::Raw, Some(EcdsaHash::Sha384)), Some(Ok(())));
        assert_eq!(
            ecdsa(spki.as_bytes(), b"m", s.to_der().as_bytes(), Encoding::Der, Some(EcdsaHash::Sha384)),
            Some(Ok(()))
        );
        assert!(matches!(
            ecdsa(spki.as_bytes(), b"x", &s.to_bytes(), Encoding::Raw, Some(EcdsaHash::Sha384)),
            Some(Err(_))
        ));
        assert!(
            matches!(ecdsa(spki.as_bytes(), b"m", &s.to_bytes(), Encoding::Raw, None), Some(Err(_))),
            "P-256's own hash is SHA-256"
        );
        assert_eq!(rsa_pkcs1v15::<Sha256>(spki.as_bytes(), b"m", &s.to_bytes()), None);
        assert_eq!(ed25519(spki.as_bytes(), b"m", &s.to_bytes()), None);
    }
}
