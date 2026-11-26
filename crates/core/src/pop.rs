//! Proof of possession (docs/DESIGN.md §3.6). The token proves that it holds the private key that
//! belongs to the public key whose hash is the identity. It does so by signing, by deriving
//! (ECDH), or by decrypting (RSA-OAEP) a fresh challenge with domain separation. The host checks
//! the result against the same canonical SPKI that `rfc7093m4` hashes. This binds a private key
//! object to its identity even when the public key comes from a separate public key object (H1
//! in docs/archive/REVIEW-2026-11-11.md).
//!
//! The verification uses the `RustCrypto` crates. No proof value is ever stored.

use crate::Check;
use crate::error::{KmError, Reason, Result};
use crate::id::{Curve, KeyAlg};
use crate::migrate::OaepHash;
use crate::sig;
pub use crate::sig::HashAlg;
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{Generate, PublicKey, ecdh::EphemeralSecret};
use hmac::{Hmac, KeyInit, Mac};
use pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The domain separator. Because a challenge starts with this ASCII text, it is never a valid
/// encoding of anything else that a key signs (certificates, CMS, SSH, ...), since none of those
/// start with this text.
pub const DOMAIN: &[u8] = b"cakeys/pop/v1\0";

/// Returns the challenge `DOMAIN ‖ SHA-256(spki) ‖ nonce`.
#[must_use]
pub fn message(spki: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, Sha256::digest(spki).as_slice(), nonce].concat()
}

/// Returns a challenge with a fresh 32-byte nonce from the OS.
///
/// # Errors
///
/// Returns `Unavailable` if the random number generator of the OS fails.
pub fn challenge(spki: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
    Ok(message(spki, &nonce))
}

/// The RSA signature that a `pop-sign` proof asks the token to make: its padding and its hash.
/// PSS uses MGF1 with the same hash and a salt as long as the hash's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignature {
    /// PKCS#1 v1.5.
    Pkcs1v15(HashAlg),
    /// PSS.
    Pss(HashAlg),
}

/// Verifies the signature `sig` over `msg` with the key in `spki`, in the form in which the token
/// produced it (`crate::sig`):
/// - ECDSA: the raw `r ‖ s` (PKCS#11) over the curve's hash of `msg` (`HashAlg::for_curve`);
/// - Ed25519: pure `EdDSA` over `msg`;
/// - RSA: with the padding and the hash that `rsa` names.
///
/// # Errors
///
/// Returns `Conflict` when the signature does not verify, which means that the private key is
/// not the key that the identity names. Returns `Unsupported` for an Ed448 key (no verifier
/// exists yet; the spec can opt in to `binding = "token-asserted"`), for a key that is none of
/// the three kinds above, or for a key that the parser of its algorithm refuses. In the last
/// case, the error gives the parser's reason, because a malformed public key is not a failed
/// proof.
pub fn verify(spki: &[u8], msg: &[u8], sig: &[u8], rsa: RsaSignature) -> Result<()> {
    let of_key = |what: &dyn std::fmt::Display| {
        KmError::Unsupported(format!("proof of possession for the public key {}: {what}", crate::id::sri(spki)).into())
    };
    // The key's own algorithm selects the verifier (ISSUES.md Q20). The code never tries each
    // verifier and takes the first one that parses the key.
    let verdict = match KeyAlg::of_spki(spki).map_err(|e| of_key(&e))? {
        KeyAlg::Ec(Curve::Ed25519) => sig::ed25519(spki, msg, sig),
        KeyAlg::Ec(Curve::Ed448) => {
            return Err(KmError::Unsupported(
                "no Ed448 signature verifier to prove possession with; opt in with binding = \"token-asserted\"".into(),
            ));
        }
        KeyAlg::Ec(_) => sig::ecdsa(spki, msg, sig, sig::Encoding::Raw, None),
        KeyAlg::Rsa => match rsa {
            RsaSignature::Pkcs1v15(HashAlg::Sha256) => sig::rsa_pkcs1v15::<Sha256>(spki, msg, sig),
            RsaSignature::Pkcs1v15(HashAlg::Sha384) => sig::rsa_pkcs1v15::<sha2::Sha384>(spki, msg, sig),
            RsaSignature::Pkcs1v15(HashAlg::Sha512) => sig::rsa_pkcs1v15::<sha2::Sha512>(spki, msg, sig),
            RsaSignature::Pss(HashAlg::Sha256) => sig::rsa_pss::<Sha256>(spki, msg, sig),
            RsaSignature::Pss(HashAlg::Sha384) => sig::rsa_pss::<sha2::Sha384>(spki, msg, sig),
            RsaSignature::Pss(HashAlg::Sha512) => sig::rsa_pss::<sha2::Sha512>(spki, msg, sig),
        },
    };
    match verdict {
        Some(Ok(())) => Ok(()),
        Some(Err(sig::Refused::Signature(e))) => Err(KmError::Conflict(Reason::check(
            Check::PopSign,
            format!(
                "proof of possession failed: the private key did not sign for the public key {} ({e})",
                crate::id::sri(spki)
            ),
        ))),
        // An RSA key of a size with which the `rsa` crate does not compute has an identity (id.rs
        // F1), but no verifier here, so the refusal names the key's size. For any other key that
        // its parser refuses, the refusal gives the parser's reason.
        Some(Err(sig::Refused::Key(why))) => match crate::id::rsa_of_spki(spki) {
            Ok(key) => Err(of_key(&format_args!(
                "an RSA key of {} bits, outside the 1024 to 8192 cakeys verifies signatures of (exponent at \
                 most 2^33 - 1; {why}); opt in with binding = \"token-asserted\"",
                rsa::traits::PublicKeyParts::n(&key).bit_width_vartime()
            ))),
            Err(_) => Err(of_key(&format_args!("its algorithm's own parser refuses it: {why}"))),
        },
        // The key's algorithm selected the verifier, so the verifier never reports that the key
        // is of another kind.
        None => Err(of_key(&"no verifier for its algorithm")),
    }
}

/// The host's side of a `pop-ecdh` proof: an ephemeral key on the key's curve, the shared secret
/// derived with the public key in `spki`, and the MAC of `msg` that the token must reproduce.
pub struct EcdhChallenge {
    /// The ephemeral public point, in uncompressed SEC1 form, for the token's `C_DeriveKey`.
    pub peer: Vec<u8>,
    /// The HMAC-SHA256 over `msg`, with the shared secret as the key.
    pub mac: Vec<u8>,
    /// The shared secret itself, for a token that can derive only into an extractable secret
    /// (ykcs11 \[src\]). The token's derived value is compared with this secret instead of a MAC.
    /// Only the host and the token know the secret, and it is used once.
    pub secret: zeroize::Zeroizing<Vec<u8>>,
}

/// Starts a `pop-ecdh` proof of possession. The function generates an ephemeral key on the curve
/// of the public key in `spki`, derives the shared secret of the ephemeral key and the public key,
/// and computes the MAC of `msg` with that secret. The token derives the same secret with
/// `CKM_ECDH1_DERIVE` and `peer`, and computes the MAC of the same `msg`. The two MACs match only
/// if the token's private key is the key that `spki` names.
///
/// # Errors
///
/// Returns `Unsupported` if no `RustCrypto` crate implements ECDH for the key's curve. Returns
/// `Unavailable` if the random number generator of the OS fails.
pub fn ecdh_challenge(spki: &[u8], msg: &[u8]) -> Result<EcdhChallenge> {
    let mut rng = getrandom::SysRng;
    let none = |what: &dyn std::fmt::Display| {
        KmError::Unsupported(format!("no RustCrypto ECDH for the public key {}: {what}", crate::id::sri(spki)).into())
    };
    macro_rules! ecdh {
        ($curve:ty) => {{
            let pk = PublicKey::<$curve>::from_public_key_der(spki).map_err(|e| none(&e))?;
            let eph = EphemeralSecret::<$curve>::try_generate_from_rng(&mut rng)
                .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
            let shared = eph.diffie_hellman(&pk);
            Ok(EcdhChallenge {
                peer: eph.public_key().to_sec1_point(false).as_bytes().to_vec(),
                mac: mac_sha256(shared.raw_secret_bytes(), msg),
                secret: zeroize::Zeroizing::new(shared.raw_secret_bytes().to_vec()),
            })
        }};
    }
    // The key's OIDs select the arithmetic of its curve (ISSUES.md Q20).
    match KeyAlg::of_spki(spki).map_err(|e| none(&e))? {
        KeyAlg::Ec(Curve::P256) => ecdh!(p256::NistP256),
        KeyAlg::Ec(Curve::P384) => ecdh!(p384::NistP384),
        KeyAlg::Ec(Curve::P521) => ecdh!(p521::NistP521),
        KeyAlg::Ec(Curve::Secp256k1) => ecdh!(k256::Secp256k1),
        KeyAlg::Ec(Curve::BrainpoolP256r1) => ecdh!(bp256::BrainpoolP256r1),
        KeyAlg::Ec(Curve::BrainpoolP384r1) => ecdh!(bp384::BrainpoolP384r1),
        KeyAlg::Ec(c @ (Curve::Ed25519 | Curve::Ed448)) => {
            Err(none(&format_args!("an {} key derives nothing", c.display())))
        }
        KeyAlg::Rsa => Err(none(&"an RSA key derives nothing")),
    }
}

/// The host's side of a `pop-unwrap` proof: a fresh secret wrapped to the public key, and the MAC
/// of the challenge with that secret, which the token must reproduce.
pub struct UnwrapChallenge {
    /// The secret, encrypted with RSA-OAEP to the public key, for the token's `C_UnwrapKey`.
    pub wrapped: Vec<u8>,
    /// The HMAC-SHA256 over `msg`, with the secret as the key.
    pub mac: Vec<u8>,
}

/// Starts a `pop-unwrap` proof of possession. The function wraps a fresh 32-byte secret to the
/// public key in `spki` with `padding` (the OAEP hash to which a token's key is bound; Cloud KMS
/// allows only SHA-256 or SHA-512 \[run\]), and computes the MAC of `msg` with the secret. The
/// token unwraps the secret with `CKM_RSA_PKCS_OAEP` into a non-extractable session key and
/// computes the MAC of the same `msg`. The two MACs match only if the token's private key is the
/// key that `spki` names. Nothing leaves the token in plaintext, because the key needs
/// `CKA_UNWRAP` and never `CKA_DECRYPT`.
///
/// # Errors
///
/// Returns `Unsupported` if `spki` is not an RSA key. Returns `Unavailable` if the random number
/// generator of the OS or the encryption fails.
pub fn unwrap_challenge(spki: &[u8], msg: &[u8], padding: RsaPadding) -> Result<UnwrapChallenge> {
    let secret = secret()?;
    Ok(UnwrapChallenge { wrapped: rsa_encrypt(spki, padding, &*secret)?, mac: mac_sha256(&*secret, msg) })
}

/// Returns a fresh 32-byte secret from the OS, which is wiped when it is dropped, as the shared
/// secret of the ECDH proof is. An RSA decryption proof or unwrap proof encrypts this secret to
/// the public key, which binds the token's answer to that key. The secret fits OAEP-SHA-256 on a
/// 1024-bit key, and the 78-byte challenge does not (review 2026-11-23 B-7).
///
/// # Errors
///
/// Returns `Unavailable` if the random number generator of the OS fails.
pub fn secret() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret)
        .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
    Ok(secret)
}

/// The RSA encryption paddings with which a decryption proof, an unwrap proof and the probe
/// encrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 (`CKM_RSA_PKCS`).
    Pkcs1v15,
    /// OAEP with MGF1 of the same hash and an empty label (`CKM_RSA_PKCS_OAEP`).
    Oaep(OaepHash),
    /// OAEP with SHA-512, which no transport uses. A proof and the probe use it for a key that is
    /// bound to it (the 4096-bit SHA-512 OAEP keys of Cloud KMS).
    OaepSha512,
}

/// Returns `msg` encrypted to the RSA public key in `spki` with `padding`.
///
/// # Errors
///
/// Returns `Unsupported` if `spki` is not an RSA key, or if `msg` is longer than the maximum that
/// `padding` allows for the key's modulus (OAEP-SHA-512 allows no message at all on a 1024-bit
/// key). Returns `Unavailable` if the random number generator of the OS or the encryption fails.
pub fn rsa_encrypt(spki: &[u8], padding: RsaPadding, msg: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("RSA encryption to this SPKI: {e}").into()))?;
    // RFC 8017 §7.1.1 and §7.2.1 give the maximum message length of a padding for a k-byte
    // modulus. A key that is too small for the message is refused because of the key's size, not
    // reported as a failure of the host (review 2026-11-23 A-11).
    let k = rsa::traits::PublicKeyParts::size(&key);
    let (name, overhead) = match padding {
        RsaPadding::Pkcs1v15 => ("PKCS #1 v1.5", 11),
        RsaPadding::Oaep(OaepHash::Sha1) => ("OAEP-SHA-1", 2 * 20 + 2),
        RsaPadding::Oaep(OaepHash::Sha256) => ("OAEP-SHA-256", 2 * 32 + 2),
        RsaPadding::OaepSha512 => ("OAEP-SHA-512", 2 * 64 + 2),
    };
    let room = k.saturating_sub(overhead);
    if msg.len() > room {
        return Err(KmError::Unsupported(
            format!(
                "RSA encryption: {name} carries at most {room} bytes in a {}-bit modulus, not {}",
                rsa::traits::PublicKeyParts::n(&key).bit_width_vartime(),
                msg.len()
            )
            .into(),
        ));
    }
    let rng = &mut getrandom::SysRng;
    match padding {
        RsaPadding::Pkcs1v15 => key.encrypt(rng, rsa::Pkcs1v15Encrypt, msg),
        RsaPadding::Oaep(OaepHash::Sha1) => key.encrypt(rng, rsa::Oaep::<sha1::Sha1>::new(), msg),
        RsaPadding::Oaep(OaepHash::Sha256) => key.encrypt(rng, rsa::Oaep::<Sha256>::new(), msg),
        RsaPadding::OaepSha512 => key.encrypt(rng, rsa::Oaep::<sha2::Sha512>::new(), msg),
    }
    .map_err(|e| KmError::Unavailable(format!("RSA encryption: {e}").into()))
}

/// Returns the length in bytes of the modulus of the RSA public key in `spki`, which is the
/// length of the block that a raw RSA operation (`CKM_RSA_X_509`) takes.
///
/// # Errors
///
/// Returns `Unsupported` if `spki` is not an RSA key.
pub fn rsa_modulus_len(spki: &[u8]) -> Result<usize> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("an RSA key in this SPKI: {e}").into()))?;
    Ok(rsa::traits::PublicKeyParts::size(&key))
}

/// Returns whether the host can compute with the RSA key in `spki`, which means verify its
/// signatures and encrypt to it. The `rsa` crate accepts 1024 to 8192 bits and an exponent up to
/// 2^33 - 1. A key outside these limits has an identity (`id::rsa_of_spki`) but no proof of
/// possession here.
#[must_use]
pub fn rsa_computes_with(spki: &[u8]) -> bool {
    rsa::PublicKey::from_public_key_der(spki).is_ok()
}

// The HMAC below uses a proof secret as its key (the ECDH shared secret or the unwrap secret).
// Its state is two SHA-256 cores that have absorbed blocks derived from the key. hmac 0.13 wipes
// nothing itself (its `zeroize` feature wipes only the block buffer), so the cores must wipe
// themselves. sha2's `zeroize` feature, which core's Cargo.toml enables, gives them a `Drop`
// that wipes them, and this item fails to build without that feature. Two values are not wiped
// by anything: the key block that hmac's `new_from_slice` derives on the stack, and the inner
// hash that `finalize_fixed_core` holds on the stack (both are upstream code).
const _: fn() = || {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<sha2::block_api::Sha256VarCore>();
};

/// Returns the HMAC-SHA256 over `msg` with `key`. HMAC accepts a key of any length.
fn mac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Compares a proof's expected value with its actual value in constant time, so that only the
/// length can be observed. It uses the `subtle` crate (already a transitive `RustCrypto`
/// dependency), and not a hand-written XOR loop, which the optimizer could turn into an early
/// exit.
#[must_use]
pub fn ct_eq(expected: &[u8], got: &[u8]) -> bool {
    bool::from(expected.ct_eq(got))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RSA signature that the PKCS#11 baseline makes: PKCS#1 v1.5 with SHA-256.
    const V15: RsaSignature = RsaSignature::Pkcs1v15(HashAlg::Sha256);

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
        use pkcs8::EncodePublicKey;
        let k1 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let k2 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let spki = k1.verifying_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let digest = sig::digest(HashAlg::Sha256, &msg);
        let good: Signature = k1.sign_prehash(&digest).unwrap();
        let other: Signature = k2.sign_prehash(&digest).unwrap();
        verify(spki.as_bytes(), &msg, &good.to_bytes(), V15).unwrap();
        assert!(matches!(verify(spki.as_bytes(), &msg, &other.to_bytes(), V15), Err(KmError::Conflict(_))));
    }

    /// A public key that the parser of its algorithm refuses is unsupported (15), and the error
    /// gives the parser's reason. It is never a failed proof (13). The cases are a malformed
    /// point, an RSA size with which the host does not compute (the error names the size), and an
    /// even modulus (review pop.rs F2).
    #[test]
    fn a_refused_public_key_is_no_failed_proof() {
        use pkcs8::EncodePublicKey;
        let ec = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap().verifying_key().to_public_key_der().unwrap();
        let mut off_curve = ec.as_bytes().to_vec();
        *off_curve.last_mut().unwrap() ^= 1;
        let rsa768 = crate::id::rsa_spki(&[&[0xc5u8][..], &[0x5a; 94], &[0x01]].concat(), &[1, 0, 1]).unwrap();
        let cases: [(&[u8], &str); 2] =
            [(&off_curve, "its algorithm's own parser refuses it: "), (&rsa768, "768 bits")];
        for (spki, said) in cases {
            for rsa in [RsaSignature::Pkcs1v15(HashAlg::Sha256), RsaSignature::Pss(HashAlg::Sha384)] {
                let e = verify(spki, b"m", &[0u8; 64], rsa).unwrap_err();
                assert!(matches!(&e, KmError::Unsupported(m) if m.contains(said)), "{said}: {e}");
            }
        }
        // The error gives the parser's own message, not a generic "does not read it".
        let e = verify(&off_curve, b"m", &[0u8; 64], V15).unwrap_err().to_string();
        let reason = e.split("refuses it: ").nth(1).unwrap_or_default();
        assert!(!reason.is_empty(), "{e}");
        let e = verify(&rsa768, b"m", &[0u8; 64], V15).unwrap_err().to_string();
        let reason = e.split("2^33 - 1; ").nth(1).and_then(|r| r.split(')').next()).unwrap_or_default();
        assert!(!reason.is_empty() && e.contains("token-asserted"), "{e}");
    }

    #[test]
    fn the_ecdh_mac_matches_on_both_sides() {
        use p256::elliptic_curve::{NonZeroScalar, ecdh::diffie_hellman};
        use pkcs8::EncodePublicKey;
        // The host performs the token's side: it derives the secret with the private key and the
        // challenge's ephemeral point, and the MACs must agree.
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
    fn the_unwrap_mac_matches_on_both_sides() {
        use pkcs8::EncodePublicKey;
        // The host performs the token's side: it decrypts the wrapped secret and computes the MAC
        // with it.
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let ch = unwrap_challenge(spki.as_bytes(), &msg, RsaPadding::Oaep(OaepHash::Sha1)).unwrap();
        let secret = private.decrypt(rsa::Oaep::<sha1::Sha1>::new(), &ch.wrapped).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(mac_sha256(&secret, &msg), ch.mac);
        assert_ne!(
            unwrap_challenge(spki.as_bytes(), &msg, RsaPadding::Oaep(OaepHash::Sha1)).unwrap().mac,
            ch.mac,
            "a fresh secret each time"
        );
    }

    /// A message longer than the maximum of the padding for the modulus is refused because of the
    /// key's size (15), and the error names the size. It is never reported as a failure of the
    /// host (16). The 32-byte proof secret fits every padding on a 1024-bit key except
    /// OAEP-SHA-512, which allows no message there (review 2026-11-23 A-11, B-7).
    #[test]
    fn a_message_too_long_for_the_modulus_is_unsupported() {
        use pkcs8::EncodePublicKey;
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let spki = spki.as_bytes();
        let challenge = message(spki, &[0u8; 32]);
        let fresh = secret().unwrap();
        for padding in [RsaPadding::Pkcs1v15, RsaPadding::Oaep(OaepHash::Sha1), RsaPadding::Oaep(OaepHash::Sha256)] {
            assert_eq!(rsa_encrypt(spki, padding, fresh.as_slice()).unwrap().len(), 128, "{padding:?}");
        }
        let e = rsa_encrypt(spki, RsaPadding::Oaep(OaepHash::Sha256), &challenge).unwrap_err();
        assert!(
            matches!(&e, KmError::Unsupported(m) if m.contains("OAEP-SHA-256 carries at most 62 bytes in a 1024-bit modulus, not 78")),
            "{e}"
        );
        let e = rsa_encrypt(spki, RsaPadding::OaepSha512, fresh.as_slice()).unwrap_err();
        assert!(matches!(&e, KmError::Unsupported(m) if m.contains("at most 0 bytes")), "{e}");
        // A message of exactly the maximum length is encrypted.
        rsa_encrypt(spki, RsaPadding::Oaep(OaepHash::Sha256), &[1u8; 62]).unwrap();
        assert_ne!(*fresh, *secret().unwrap(), "a fresh secret each time");
    }

    #[test]
    fn ecdh_needs_a_supported_curve() {
        use pkcs8::EncodePublicKey;
        // Edwards keys have no RustCrypto ECDH here, so the challenge is refused, and no wrong
        // proof is made without an error.
        let spki = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_public_key_der().unwrap();
        assert!(matches!(ecdh_challenge(spki.as_bytes(), b"m"), Err(KmError::Unsupported(_))));
    }

    /// The RSA proofs, with the host performing the token's side. A PKCS#1 v1.5 SHA-256 signature
    /// verifies only for its key and its message. An OAEP challenge decrypts back to the message
    /// with the private key, and each encryption is different.
    #[test]
    fn rsa_proofs_hold_for_the_key_alone() {
        use pkcs8::EncodePublicKey;
        use rsa::signature::{SignatureEncoding as _, Signer as _};
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private.clone());
        let signature = signer.sign(b"message").to_vec();
        verify(spki.as_bytes(), b"message", &signature, V15).unwrap();
        assert!(matches!(verify(spki.as_bytes(), b"another", &signature, V15), Err(KmError::Conflict(_))));

        let challenge = rsa_encrypt(spki.as_bytes(), RsaPadding::Oaep(OaepHash::Sha1), b"message").unwrap();
        assert_eq!(private.decrypt(rsa::Oaep::<sha1::Sha1>::new(), &challenge).unwrap(), b"message");
        assert_ne!(rsa_encrypt(spki.as_bytes(), RsaPadding::Oaep(OaepHash::Sha1), b"message").unwrap(), challenge);
        assert!(matches!(
            rsa_encrypt(b"no key", RsaPadding::Oaep(OaepHash::Sha1), b"message"),
            Err(KmError::Unsupported(_))
        ));

        assert_eq!(rsa_modulus_len(spki.as_bytes()).unwrap(), 256);
        assert!(matches!(rsa_modulus_len(b"no key"), Err(KmError::Unsupported(_))));
    }

    /// A key that is bound to another RSA signature makes its proof with that signature. PSS with
    /// SHA-256 (with a salt as long as the hash) and PKCS#1 v1.5 with SHA-512 verify as requested,
    /// and they do not verify as another scheme or hash.
    #[test]
    fn rsa_signatures_verify_as_the_key_is_bound() {
        use pkcs8::EncodePublicKey;
        use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let spki = spki.as_bytes();
        let pss = rsa::pss::SigningKey::<Sha256>::new(private.clone())
            .try_sign_with_rng(&mut getrandom::SysRng, b"message")
            .unwrap()
            .to_vec();
        verify(spki, b"message", &pss, RsaSignature::Pss(HashAlg::Sha256)).unwrap();
        for other in [RsaSignature::Pss(HashAlg::Sha512), RsaSignature::Pkcs1v15(HashAlg::Sha256)] {
            assert!(matches!(verify(spki, b"message", &pss, other), Err(KmError::Conflict(_))), "{other:?}");
        }
        let v15 = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private.clone()).sign(b"message").to_vec();
        verify(spki, b"message", &v15, RsaSignature::Pkcs1v15(HashAlg::Sha512)).unwrap();
        assert!(
            matches!(verify(spki, b"message", &v15, V15), Err(KmError::Conflict(_))),
            "v1.5 over SHA-512 is not over SHA-256"
        );
        // The unwrap challenge uses the OAEP hash to which the key is bound.
        let ch = unwrap_challenge(spki, b"m", RsaPadding::OaepSha512).unwrap();
        assert_eq!(private.decrypt(rsa::Oaep::<sha2::Sha512>::new(), &ch.wrapped).unwrap().len(), 32);
    }
}
