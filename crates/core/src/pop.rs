//! Proof of possession (docs/DESIGN.md §3.6): the token proves it holds the private key that
//! belongs to the public key the identity hashes — by signing, by deriving (ECDH), or by
//! decrypting (RSA-OAEP) a fresh, domain-separated challenge — and the host checks the result
//! against the same canonical SPKI that `rfc7093m4` hashes. This binds a private-key object to
//! its identity even when the public key comes from a separate public-key object (H1 in
//! docs/archive/REVIEW-2026-11-11.md).
//!
//! Verification uses the `RustCrypto` crates; no proof value is ever stored.

use crate::error::{KmError, Result};
use crate::id::{Curve, KeyAlg};
use crate::sig;
pub use crate::sig::HashAlg;
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{Generate, PublicKey, ecdh::EphemeralSecret};
use hmac::{Hmac, KeyInit, Mac};
use pkcs8::DecodePublicKey;
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
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
    Ok(message(spki, &nonce))
}

/// The RSA signature a `pop-sign` proof asks of the token: its padding and hash. PSS uses MGF1
/// of the same hash and a salt as long as its output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignature {
    /// PKCS#1 v1.5.
    Pkcs1v15(HashAlg),
    /// PSS.
    Pss(HashAlg),
}

/// Verify `sig` over `msg` with the key in `spki`, as the token produced it (`crate::sig`):
/// - ECDSA: raw `r ‖ s` (PKCS#11) over the curve's hash of `msg` (`HashAlg::for_curve`);
/// - Ed25519: pure `EdDSA` over `msg`;
/// - RSA: PKCS#1 v1.5 with SHA-256 over `msg`.
///
/// # Errors
///
/// As [`verify_with`].
pub fn verify(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    verify_with(spki, msg, sig, RsaSignature::Pkcs1v15(HashAlg::Sha256))
}

/// [`verify`], with an RSA key's signature made as `rsa` says.
///
/// # Errors
///
/// `Conflict` when the signature does not verify: the private key is not the one the identity
/// names. `Unsupported` for an Ed448 key (no verifier yet: opt in with
/// `binding = "token-asserted"`), a key that is none of the three above, or one its
/// algorithm's own parser refuses, with the parser's reason: a malformed public key is no
/// failed proof.
pub fn verify_with(spki: &[u8], msg: &[u8], sig: &[u8], rsa: RsaSignature) -> Result<()> {
    let of_key = |what: &dyn std::fmt::Display| {
        KmError::Unsupported(format!("proof of possession for the public key {}: {what}", crate::id::sri(spki)).into())
    };
    // The verifier the key's own algorithm takes (ISSUES.md Q20), never the first that parses.
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
        Some(Err(sig::Refused::Signature(e))) => Err(KmError::Conflict(
            format!(
                "proof of possession failed: the private key did not sign for the public key {} ({e})",
                crate::id::sri(spki)
            )
            .into(),
        )),
        // An RSA key of a size `rsa` does not compute with has its identity (id.rs F1), but
        // no verifier here: the refusal says so, by its size. Any other key its parser refuses
        // is named with the parser's reason.
        Some(Err(sig::Refused::Key(why))) => match crate::id::rsa_of_spki(spki) {
            Ok(key) => Err(of_key(&format_args!(
                "an RSA key of {} bits, outside the 1024 to 8192 cakeys verifies signatures of (exponent at \
                 most 2^33 - 1; {why}); opt in with binding = \"token-asserted\"",
                rsa::traits::PublicKeyParts::n(&key).bit_width_vartime()
            ))),
            Err(_) => Err(of_key(&format_args!("its algorithm's own parser refuses it: {why}"))),
        },
        // The verifier was chosen by the key's algorithm, so it never answers "another kind".
        None => Err(of_key(&"no verifier for its algorithm")),
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
    /// (ykcs11 \[src\]): the token's derived value is compared with it instead of a MAC. Secret
    /// only to the two ephemeral parties, and used once.
    pub secret: zeroize::Zeroizing<Vec<u8>>,
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
    // The curve's own arithmetic, by the key's OIDs (ISSUES.md Q20).
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

/// The host side of a `pop-unwrap` proof: a fresh secret wrapped to the public key, and the MAC
/// of the challenge under it that the token must reproduce.
pub struct UnwrapChallenge {
    /// The secret, RSA-OAEP (SHA-1) to the public key, for the token's `C_UnwrapKey`.
    pub wrapped: Vec<u8>,
    /// HMAC-SHA256 over `msg` keyed with the secret.
    pub mac: Vec<u8>,
}

/// Start a `pop-unwrap` proof of possession: a fresh 32-byte secret, wrapped to the public key in
/// `spki` with RSA-OAEP (SHA-1, the baseline `pop-decrypt` uses), and the MAC of `msg` under it.
/// The token unwraps it with `CKM_RSA_PKCS_OAEP` into a non-extractable session key and MACs the
/// same `msg`; the MACs match only if the token's private key is the one `spki` names. Nothing
/// leaves the token in plaintext: the key needs `CKA_UNWRAP`, never `CKA_DECRYPT`.
///
/// # Errors
///
/// `Unsupported` if `spki` is not an RSA key; `Unavailable` if the OS random number generator
/// or the encryption fails.
pub fn unwrap_challenge(spki: &[u8], msg: &[u8]) -> Result<UnwrapChallenge> {
    unwrap_challenge_with(spki, msg, RsaPadding::Oaep(OaepHash::Sha1))
}

/// [`unwrap_challenge`], the secret wrapped with `padding`: the OAEP hash a token's key is bound
/// to (Cloud KMS: SHA-256 or SHA-512 only \[run\]).
///
/// # Errors
///
/// As [`unwrap_challenge`].
pub fn unwrap_challenge_with(spki: &[u8], msg: &[u8], padding: RsaPadding) -> Result<UnwrapChallenge> {
    // Wiped when dropped, as the ECDH proof's shared secret is: the key the token unwraps.
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret)
        .map_err(|e| KmError::Unavailable(format!("OS random number generator: {e}").into()))?;
    Ok(UnwrapChallenge { wrapped: rsa_encrypt(spki, padding, &*secret)?, mac: mac_sha256(&*secret, msg) })
}

/// The RSA-OAEP hash, with MGF1 of the same hash: a transport wrap's and an OAEP proof's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OaepHash {
    /// SHA-1, with MGF1-SHA-1.
    Sha1,
    /// SHA-256, with MGF1-SHA-256.
    Sha256,
}

/// The RSA encryption paddings a decryption or unwrap proof, and the probe, encrypt with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS#1 v1.5 (`CKM_RSA_PKCS`).
    Pkcs1v15,
    /// OAEP with MGF1 of the same hash and an empty label (`CKM_RSA_PKCS_OAEP`).
    Oaep(OaepHash),
    /// OAEP over SHA-512, which no transport uses: a proof and the probe ask it of a key bound
    /// to it (Cloud KMS's 4096-bit SHA-512 OAEP keys).
    OaepSha512,
}

/// `msg` encrypted to the RSA public key in `spki` with `padding`.
///
/// # Errors
///
/// `Unsupported` if `spki` is not an RSA key; `Unavailable` if the OS random number generator
/// or the encryption fails (for instance, `msg` is too long for the modulus).
pub fn rsa_encrypt(spki: &[u8], padding: RsaPadding, msg: &[u8]) -> Result<Vec<u8>> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("RSA encryption to this SPKI: {e}").into()))?;
    let rng = &mut getrandom::SysRng;
    match padding {
        RsaPadding::Pkcs1v15 => key.encrypt(rng, rsa::Pkcs1v15Encrypt, msg),
        RsaPadding::Oaep(OaepHash::Sha1) => key.encrypt(rng, rsa::Oaep::<sha1::Sha1>::new(), msg),
        RsaPadding::Oaep(OaepHash::Sha256) => key.encrypt(rng, rsa::Oaep::<Sha256>::new(), msg),
        RsaPadding::OaepSha512 => key.encrypt(rng, rsa::Oaep::<sha2::Sha512>::new(), msg),
    }
    .map_err(|e| KmError::Unavailable(format!("RSA encryption: {e}").into()))
}

/// The length in bytes of the modulus of the RSA public key in `spki`: the block a raw RSA
/// operation (`CKM_RSA_X_509`) takes.
///
/// # Errors
///
/// `Unsupported` if `spki` is not an RSA key.
pub fn rsa_modulus_len(spki: &[u8]) -> Result<usize> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Unsupported(format!("an RSA key in this SPKI: {e}").into()))?;
    Ok(rsa::traits::PublicKeyParts::size(&key))
}

/// Whether the host computes with the RSA key in `spki`: verifies its signatures, encrypts to
/// it. The `rsa` crate takes 1024 to 8192 bits and an exponent up to 2^33 - 1; a key outside
/// has an identity (`id::rsa_of_spki`) but no proof of possession here.
#[must_use]
pub fn rsa_computes_with(spki: &[u8]) -> bool {
    rsa::PublicKey::from_public_key_der(spki).is_ok()
}

// The HMAC below is keyed with a proof secret (the ECDH shared secret, the unwrap secret); its
// state is two SHA-256 cores fed with key-derived blocks. hmac 0.13 wipes nothing itself (its
// `zeroize` feature wipes only the block buffer), so the cores must wipe themselves: sha2's
// `zeroize` feature, which core's Cargo.toml enables, gives them a wiping `Drop`. This fails to
// build without it. Not wiped by anything: the key block hmac's `new_from_slice` derives on the
// stack, and the inner hash `finalize_fixed_core` holds on the stack (upstream code).
const _: fn() = || {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<sha2::block_api::Sha256VarCore>();
};

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
        use pkcs8::EncodePublicKey;
        let k1 = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let k2 = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let spki = k1.verifying_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let digest = HashAlg::Sha256.digest(&msg);
        let good: Signature = k1.sign_prehash(&digest).unwrap();
        let other: Signature = k2.sign_prehash(&digest).unwrap();
        verify(spki.as_bytes(), &msg, &good.to_bytes()).unwrap();
        assert!(matches!(verify(spki.as_bytes(), &msg, &other.to_bytes()), Err(KmError::Conflict(_))));
    }

    /// A public key its algorithm's parser refuses is unsupported (15), with the parser's
    /// reason, never a failed proof (13): a malformed point, an RSA size the host does not
    /// compute with (named by its size), an even modulus (review pop.rs F2).
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
                let e = verify_with(spki, b"m", &[0u8; 64], rsa).unwrap_err();
                assert!(matches!(&e, KmError::Unsupported(m) if m.contains(said)), "{said}: {e}");
            }
        }
        // The parser's own words follow, not a generic "does not read it".
        let e = verify(&off_curve, b"m", &[0u8; 64]).unwrap_err().to_string();
        let reason = e.split("refuses it: ").nth(1).unwrap_or_default();
        assert!(!reason.is_empty(), "{e}");
        let e = verify(&rsa768, b"m", &[0u8; 64]).unwrap_err().to_string();
        let reason = e.split("2^33 - 1; ").nth(1).and_then(|r| r.split(')').next()).unwrap_or_default();
        assert!(!reason.is_empty() && e.contains("token-asserted"), "{e}");
    }

    #[test]
    fn the_ecdh_mac_matches_on_both_sides() {
        use p256::elliptic_curve::{NonZeroScalar, ecdh::diffie_hellman};
        use pkcs8::EncodePublicKey;
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
    fn the_unwrap_mac_matches_on_both_sides() {
        use pkcs8::EncodePublicKey;
        // The token side, played on the host: decrypt the wrapped secret and MAC with it.
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let msg = message(spki.as_bytes(), &[0u8; 32]);
        let ch = unwrap_challenge(spki.as_bytes(), &msg).unwrap();
        let secret = private.decrypt(rsa::Oaep::<sha1::Sha1>::new(), &ch.wrapped).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(mac_sha256(&secret, &msg), ch.mac);
        assert_ne!(unwrap_challenge(spki.as_bytes(), &msg).unwrap().mac, ch.mac, "a fresh secret each time");
    }

    #[test]
    fn ecdh_needs_a_supported_curve() {
        use pkcs8::EncodePublicKey;
        // Edwards keys have no RustCrypto ECDH here: refused, not silently misproven.
        let spki = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_public_key_der().unwrap();
        assert!(matches!(ecdh_challenge(spki.as_bytes(), b"m"), Err(KmError::Unsupported(_))));
    }

    /// The RSA proofs, the token side played on the host: a PKCS#1 v1.5 SHA-256 signature
    /// verifies for its key and message only, and an OAEP challenge decrypts back to the
    /// message under the private key, fresh each time.
    #[test]
    fn rsa_proofs_hold_for_the_key_alone() {
        use pkcs8::EncodePublicKey;
        use rsa::signature::{SignatureEncoding as _, Signer as _};
        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private.clone());
        let signature = signer.sign(b"message").to_vec();
        verify(spki.as_bytes(), b"message", &signature).unwrap();
        assert!(matches!(verify(spki.as_bytes(), b"another", &signature), Err(KmError::Conflict(_))));

        let challenge = oaep_challenge(spki.as_bytes(), b"message").unwrap();
        assert_eq!(private.decrypt(rsa::Oaep::<sha1::Sha1>::new(), &challenge).unwrap(), b"message");
        assert_ne!(oaep_challenge(spki.as_bytes(), b"message").unwrap(), challenge);
        assert!(matches!(oaep_challenge(b"no key", b"message"), Err(KmError::Unsupported(_))));

        assert_eq!(rsa_modulus_len(spki.as_bytes()).unwrap(), 256);
        assert!(matches!(rsa_modulus_len(b"no key"), Err(KmError::Unsupported(_))));
    }

    /// A key bound to another RSA signature proves in it: PSS over SHA-256 (salt as long as the
    /// hash) and PKCS#1 v1.5 over SHA-512 verify as asked, and not as another scheme or hash.
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
        verify_with(spki, b"message", &pss, RsaSignature::Pss(HashAlg::Sha256)).unwrap();
        for other in [RsaSignature::Pss(HashAlg::Sha512), RsaSignature::Pkcs1v15(HashAlg::Sha256)] {
            assert!(matches!(verify_with(spki, b"message", &pss, other), Err(KmError::Conflict(_))), "{other:?}");
        }
        let v15 = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private.clone()).sign(b"message").to_vec();
        verify_with(spki, b"message", &v15, RsaSignature::Pkcs1v15(HashAlg::Sha512)).unwrap();
        assert!(matches!(verify(spki, b"message", &v15), Err(KmError::Conflict(_))), "verify is v1.5 over SHA-256");
        // The unwrap challenge in the OAEP hash a key is bound to.
        let ch = unwrap_challenge_with(spki, b"m", RsaPadding::OaepSha512).unwrap();
        assert_eq!(private.decrypt(rsa::Oaep::<sha2::Sha512>::new(), &ch.wrapped).unwrap().len(), 32);
    }
}
