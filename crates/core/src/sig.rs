//! The signature verification that every proof that cakeys checks on the host uses: the proof
//! of possession (`pop`), the `YubiKey` PIV attestation chain and the `TPM2_Certify` signature of
//! the TPM Attestation Key. A caller selects the function by the algorithm of the key or of the
//! signature (ISSUES.md Q20). Each function returns `None` only when the SPKI's OIDs name a
//! different kind of key (or when the bytes are not an SPKI). For a key of the function's own
//! kind, it always returns `Some`: `Ok` when the signature verifies, and otherwise the reason
//! ([`Refused`]), which is that the key's own parser refused the key, or that the signature is
//! malformed or wrong. The callers write their own error messages.

use crate::id::{Curve, KeyAlg};
use ecdsa::signature::Verifier;
use ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// `Some(Ok(()))` means that the signature verified, `Some(Err(why))` means that it did not, and
/// `None` means that the SPKI names a different kind of key.
pub type Verdict = Option<Result<(), Refused>>;

/// The reason why a key of a verifier's own kind did not verify a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The key's own parser refused the key (for example, a malformed point, or an RSA size that
    /// the `rsa` crate does not compute with), so no signature was checked.
    Key(String),
    /// The signature is malformed or does not verify.
    Signature(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Key(why) => write!(f, "the public key: {why}"),
            Refused::Signature(why) => f.write_str(why),
        }
    }
}

/// Returns the key in `spki` if its algorithm is one that `kind` accepts. Returns `None` for a
/// different kind (or for bytes that are not an SPKI), and `Some(Err)` when the key's own parser
/// refuses it.
fn key_of<'a, K>(spki: &'a [u8], kind: impl Fn(KeyAlg) -> bool) -> Option<Result<K, Refused>>
where
    K: TryFrom<pkcs8::SubjectPublicKeyInfoRef<'a>>,
    K::Error: std::fmt::Display,
{
    let (alg, info) = KeyAlg::read_spki(spki).ok()?;
    kind(alg).then(|| K::try_from(info).map_err(|e| Refused::Key(e.to_string())))
}

/// Converts the outcome of a signature check into a result whose error is a
/// [`Refused::Signature`].
fn checked<E: std::fmt::Display>(r: Result<(), E>) -> Result<(), Refused> {
    r.map_err(|e| Refused::Signature(e.to_string()))
}

/// A SHA-2 hash over which a signature is made (`cakeys_names::HashAlg`). For ECDSA on each
/// Weierstrass curve, it is the hash that matches the curve's strength ([`HashAlg::for_curve`],
/// which is the one table that both the token's signature and this module's check read). It is
/// also the hash of an RSA PKCS#1 v1.5 or PSS signature.
pub use cakeys_names::HashAlg;

/// Returns `msg` hashed with `hash`.
#[must_use]
pub fn digest(hash: HashAlg, msg: &[u8]) -> Vec<u8> {
    match hash {
        HashAlg::Sha256 => Sha256::digest(msg).to_vec(),
        HashAlg::Sha384 => Sha384::digest(msg).to_vec(),
        HashAlg::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

/// How an ECDSA signature is encoded: as raw `r ‖ s` (PKCS#11, TPM) or as DER (X.509).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `r ‖ s`, each with the curve's length, as PKCS#11 and the TPM encode it.
    Raw,
    /// An ASN.1 `Ecdsa-Sig-Value`, as X.509 encodes it.
    Der,
}

/// Verifies an ECDSA signature over `msg` with the key in `spki` (P-256/384/521, secp256k1,
/// brainpoolP256r1/P384r1). The message is hashed with `hash`, or with the curve's own hash when
/// `hash` is `None`. Both the low and the high `s` are accepted: the secp256k1 verifier requires
/// the low `s`, so the signature is normalized first.
#[must_use]
pub fn ecdsa(spki: &[u8], msg: &[u8], sig: &[u8], encoding: Encoding, hash: Option<HashAlg>) -> Verdict {
    ecdsa_over(spki, sig, encoding, |own| digest(hash.unwrap_or(own), msg))
}

/// Verifies an ECDSA signature over `digest`, which the caller computed with a hash that
/// [`HashAlg`] does not name (the hash of `CKM_ECDSA_SHA224`). The probe verifies what it signs,
/// so a mechanism that is not listed is added only after a signature that verified (review
/// 2026-11-23 D-2).
#[must_use]
pub fn ecdsa_prehash(spki: &[u8], digest: &[u8], sig: &[u8], encoding: Encoding) -> Verdict {
    ecdsa_over(spki, sig, encoding, |_| digest.to_vec())
}

/// Works as [`ecdsa()`], with the digest that the closure `digest` computes from the curve's own
/// hash. [`HashAlg::for_curve`] names that hash, which is the hash that the token was asked to
/// sign with (review 2026-11-24 A-8). Only the `RustCrypto` type differs between the curves here.
fn ecdsa_over(spki: &[u8], sig: &[u8], encoding: Encoding, digest: impl FnOnce(HashAlg) -> Vec<u8>) -> Verdict {
    macro_rules! curve {
        ($curve:ty, $own:expr, $info:expr) => {{
            let k = match p256::elliptic_curve::PublicKey::<$curve>::try_from($info) {
                Ok(k) => k,
                Err(e) => return Some(Err(Refused::Key(e.to_string()))),
            };
            let sig = match encoding {
                Encoding::Raw => ecdsa::Signature::<$curve>::from_slice(sig),
                Encoding::Der => ecdsa::Signature::<$curve>::from_der(sig),
            };
            let sig = match sig {
                Ok(s) => s.normalize_s(),
                Err(e) => return Some(Err(Refused::Signature(e.to_string()))),
            };
            let digest = digest($own);
            Some(checked(ecdsa::VerifyingKey::<$curve>::from(k).verify_prehash(&digest, &sig)))
        }};
    }
    // The curve is the one that the key's OIDs name (ISSUES.md Q20), and the SPKI is decoded
    // once. Any other key, including an Edwards key (which has no ECDSA hash), is not an ECDSA
    // key.
    let (KeyAlg::Ec(c), info) = KeyAlg::read_spki(spki).ok()? else { return None };
    let own = HashAlg::for_curve(c)?;
    match c {
        Curve::P256 => curve!(p256::NistP256, own, info),
        Curve::P384 => curve!(p384::NistP384, own, info),
        Curve::P521 => curve!(p521::NistP521, own, info),
        Curve::Secp256k1 => curve!(k256::Secp256k1, own, info),
        Curve::BrainpoolP256r1 => curve!(bp256::BrainpoolP256r1, own, info),
        Curve::BrainpoolP384r1 => curve!(bp384::BrainpoolP384r1, own, info),
        Curve::Ed25519 | Curve::Ed448 => None,
    }
}

/// Verifies a pure Ed25519 signature over `msg` (with strict verification).
#[must_use]
pub fn ed25519(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict {
    let key = key_of::<ed25519_dalek::VerifyingKey>(spki, |a| a == KeyAlg::Ec(Curve::Ed25519))?;
    Some(key.and_then(|k| checked(ed25519_dalek::Signature::from_slice(sig).and_then(|s| k.verify_strict(msg, &s)))))
}

/// Verifies an RSA PKCS#1 v1.5 signature over `msg` with the digest `D`. A key outside the range
/// of 1024 to 8192 bits that the `rsa` crate computes with is [`Refused::Key`].
#[must_use]
pub fn rsa_pkcs1v15<D>(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict
where
    D: Digest + sha2::digest::const_oid::AssociatedOid,
{
    let key = key_of::<rsa::PublicKey>(spki, |a| a == KeyAlg::Rsa)?;
    Some(key.and_then(|k| {
        checked(
            rsa::pkcs1v15::Signature::try_from(sig)
                .and_then(|s| rsa::pkcs1v15::VerifyingKey::<D>::new(k).verify(msg, &s)),
        )
    }))
}

/// Verifies an RSA-PSS signature over `msg` with the digest `D`, MGF1 with `D`, and a salt as
/// long as the output of `D` (which is what a proof asks the token for). A key that the `rsa`
/// crate does not compute with is [`Refused::Key`].
#[must_use]
pub fn rsa_pss<D>(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict
where
    D: Digest + sha2::digest::FixedOutputReset,
{
    let key = key_of::<rsa::PublicKey>(spki, |a| a == KeyAlg::Rsa)?;
    Some(key.and_then(|k| {
        checked(rsa::pss::Signature::try_from(sig).and_then(|s| rsa::pss::VerifyingKey::<D>::new(k).verify(msg, &s)))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One P-256 key signs the same message as raw `r ‖ s` and as DER. Both signatures verify, a
    /// message with a flipped bit does not, and a key of a different kind returns `None`.
    #[test]
    fn ecdsa_encodings_and_kinds() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use pkcs8::EncodePublicKey;
        let k = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        let s: Signature = k.sign_prehash(&digest(HashAlg::Sha384, b"m")).unwrap();
        assert_eq!(ecdsa(spki.as_bytes(), b"m", &s.to_bytes(), Encoding::Raw, Some(HashAlg::Sha384)), Some(Ok(())));
        assert_eq!(
            ecdsa(spki.as_bytes(), b"m", s.to_der().as_bytes(), Encoding::Der, Some(HashAlg::Sha384)),
            Some(Ok(()))
        );
        assert!(matches!(
            ecdsa(spki.as_bytes(), b"x", &s.to_bytes(), Encoding::Raw, Some(HashAlg::Sha384)),
            Some(Err(Refused::Signature(_)))
        ));
        assert!(
            matches!(
                ecdsa(spki.as_bytes(), b"m", &s.to_bytes(), Encoding::Raw, None),
                Some(Err(Refused::Signature(_)))
            ),
            "P-256's own hash is SHA-256"
        );
        assert_eq!(rsa_pkcs1v15::<Sha256>(spki.as_bytes(), b"m", &s.to_bytes()), None);
        assert_eq!(ed25519(spki.as_bytes(), b"m", &s.to_bytes()), None);
    }

    /// On every curve, the hash with which the token is asked to sign ([`HashAlg::for_curve`],
    /// as `Token::prove_sign` asks for it) is the hash with which the host verifies
    /// (`ecdsa(.., None)`). Its output is as long as the curve's field, and SHA-512 for the 66
    /// bytes of P-521. The test takes the field size from the curve crate, not from this table
    /// (review 2026-11-24 A-8). Each curve signs with its own crate.
    #[test]
    fn every_curve_verifies_with_the_hash_it_signs_with() {
        use elliptic_curve::array::typenum::Unsigned;
        use pkcs8::EncodePublicKey;
        macro_rules! signs {
            ($curve:ty, $c:expr) => {{
                let field = <<$curve as elliptic_curve::Curve>::FieldBytesSize as Unsigned>::USIZE;
                let key = ecdsa::SigningKey::<$curve>::from_slice(&vec![1u8; field]).unwrap();
                let spki = key.verifying_key().to_public_key_der().unwrap();
                let hash = HashAlg::for_curve($c).unwrap_or_else(|| panic!("{:?}: no ECDSA hash", $c));
                // The RFC 6979 nonce is derived with SHA-256 for every curve, because the
                // brainpool crates sign only with a digest feature that this build does not enable.
                let z = digest(hash, b"m");
                let (signed, _) =
                    ecdsa::hazmat::sign_prehashed_rfc6979::<$curve, Sha256>(key.as_nonzero_scalar(), &z, &[]);
                (field, hash, spki, signed.to_bytes().to_vec())
            }};
        }
        let mut seen = Vec::new();
        for c in Curve::ALL.into_iter().filter(|c| !c.edwards()) {
            let (field, hash, spki, signed) = match c {
                Curve::P256 => signs!(p256::NistP256, c),
                Curve::P384 => signs!(p384::NistP384, c),
                Curve::P521 => signs!(p521::NistP521, c),
                Curve::Secp256k1 => signs!(k256::Secp256k1, c),
                Curve::BrainpoolP256r1 => signs!(bp256::BrainpoolP256r1, c),
                Curve::BrainpoolP384r1 => signs!(bp384::BrainpoolP384r1, c),
                Curve::Ed25519 | Curve::Ed448 => unreachable!("filtered"),
            };
            assert_eq!(digest(hash, b"").len(), field.min(64), "{c:?}: {hash:?}");
            assert_eq!(ecdsa(spki.as_bytes(), b"m", &signed, Encoding::Raw, None), Some(Ok(())), "{c:?}");
            seen.push(c);
        }
        assert_eq!(seen.len(), 6, "{seen:?}");
        // An Edwards key is not an ECDSA key, whatever its bytes are.
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_public_key_der().unwrap();
        assert_eq!(ecdsa(ed.as_bytes(), b"m", &[0; 64], Encoding::Raw, None), None);
    }

    /// ECDSA over a digest that the caller computed with a hash that `HashAlg` does not name: a
    /// P-256 signature over SHA-224 verifies against that digest and against no other digest
    /// (review 2026-11-23 D-2).
    #[test]
    fn ecdsa_over_a_callers_digest() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use pkcs8::EncodePublicKey;
        let k = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        let digest = sha2::Sha224::digest(b"m");
        let s: Signature = k.sign_prehash(&digest).unwrap();
        assert_eq!(ecdsa_prehash(spki.as_bytes(), &digest, &s.to_bytes(), Encoding::Raw), Some(Ok(())));
        assert!(matches!(
            ecdsa_prehash(spki.as_bytes(), &sha2::Sha224::digest(b"x"), &s.to_bytes(), Encoding::Raw),
            Some(Err(Refused::Signature(_)))
        ));
        assert!(matches!(ecdsa(spki.as_bytes(), b"m", &s.to_bytes(), Encoding::Raw, None), Some(Err(_))));
    }

    /// `None` has one meaning: the SPKI names a different kind of key (or the bytes are not an
    /// SPKI). A key of the verifier's own kind that its parser refuses is `Some(Err(Key))`, with
    /// the parser's reason, for every verifier in the same way (review sig.rs F1).
    #[test]
    fn none_is_another_kind_and_a_refused_key_says_why() {
        use pkcs8::EncodePublicKey;
        // An SPKI whose OIDs name the kind, with key bytes that the parser of that kind refuses.
        let refused = |spki: &[u8]| {
            let mut bad = spki.to_vec();
            *bad.last_mut().unwrap() ^= 0x01;
            bad
        };
        let p256 =
            p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap().verifying_key().to_public_key_der().unwrap();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_public_key_der().unwrap();
        // An Ed25519 SPKI that holds 31 bytes, which is not an Ed25519 key.
        let ed_short =
            [&[0x30, 0x29, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x20, 0x00][..], &[7; 31]].concat();
        // RSA-768: an RSA key that the `rsa` crate does not compute with.
        let small = crate::id::rsa_spki(&[&[0xc5u8][..], &[0x5a; 94], &[0x01]].concat(), &[1, 0, 1]).unwrap();
        let sig = [0u8; 64];
        let cases: [(&str, Verdict); 4] = [
            ("ecdsa", ecdsa(&refused(p256.as_bytes()), b"m", &sig, Encoding::Raw, None)),
            ("ed25519", ed25519(&ed_short, b"m", &sig)),
            ("rsa-pkcs1v15", rsa_pkcs1v15::<Sha256>(&small, b"m", &sig)),
            ("rsa-pss", rsa_pss::<Sha256>(&small, b"m", &sig)),
        ];
        for (what, verdict) in cases {
            assert!(matches!(&verdict, Some(Err(Refused::Key(why))) if !why.is_empty()), "{what}: {verdict:?}");
            assert!(verdict.unwrap().unwrap_err().to_string().starts_with("the public key: "), "{what}");
        }
        // Bytes that are not an SPKI, or an SPKI of a different kind: each verifier returns
        // `None`.
        for spki in [&b"no key"[..], ed.as_bytes()] {
            assert_eq!(ecdsa(spki, b"m", &sig, Encoding::Raw, None), None);
            assert_eq!(rsa_pkcs1v15::<Sha256>(spki, b"m", &sig), None);
            assert_eq!(rsa_pss::<Sha256>(spki, b"m", &sig), None);
        }
        assert_eq!(ed25519(p256.as_bytes(), b"m", &sig), None);
        assert_eq!(ed25519(&small, b"m", &sig), None);
    }
}
