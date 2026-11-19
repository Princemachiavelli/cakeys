//! Signature verification shared by every proof cakeys checks on the host: proof of possession
//! (`pop`), the `YubiKey` PIV attestation chain and the TPM Attestation Key's `TPM2_Certify`
//! signature. A caller picks the function by the key's algorithm or the signature's (ISSUES.md
//! Q20). Each answers `None` only when the SPKI's OIDs name another kind of key (or it is no
//! SPKI): a key of the function's own kind always gets `Some`, `Ok` when the signature verifies,
//! else why not ([`Refused`]): its own parser refused the key, or the signature is malformed or
//! wrong. Callers word their own errors.

use crate::id::{Curve, KeyAlg};
use ecdsa::signature::Verifier;
use ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// `Some(Ok(()))` verified; `Some(Err(why))` not; `None` the SPKI names another kind of key.
pub type Verdict = Option<Result<(), Refused>>;

/// Why a key of a verifier's own kind did not verify a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The key's own parser refused it (a malformed point, an RSA size the `rsa` crate does not
    /// compute with): no signature was checked.
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

/// The key in `spki` if it is of `kind`'s algorithm: `None` for another kind (or no SPKI),
/// `Some(Err)` when its own parser refuses it.
fn key_of<'a, K>(spki: &'a [u8], kind: impl Fn(KeyAlg) -> bool) -> Option<Result<K, Refused>>
where
    K: TryFrom<pkcs8::SubjectPublicKeyInfoRef<'a>>,
    K::Error: std::fmt::Display,
{
    let (alg, info) = KeyAlg::read_spki(spki).ok()?;
    kind(alg).then(|| K::try_from(info).map_err(|e| Refused::Key(e.to_string())))
}

/// A signature check's outcome as [`Refused::Signature`].
fn checked<E: std::fmt::Display>(r: Result<(), E>) -> Result<(), Refused> {
    r.map_err(|e| Refused::Signature(e.to_string()))
}

/// A SHA-2 hash a signature is made over: ECDSA's on each Weierstrass curve, the one matching
/// its strength (FIPS 186-5, [`HashAlg::for_curve`]), and an RSA PKCS#1 v1.5 or PSS signature's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256: P-256, secp256k1, brainpoolP256r1.
    Sha256,
    /// SHA-384: P-384, brainpoolP384r1.
    Sha384,
    /// SHA-512: P-521.
    Sha512,
}

impl HashAlg {
    /// The hash for ECDSA on `curve`; `None` for an Edwards curve, which hashes inside the
    /// signature.
    #[must_use]
    pub fn for_curve(curve: Curve) -> Option<HashAlg> {
        match curve {
            Curve::P256 | Curve::Secp256k1 | Curve::BrainpoolP256r1 => Some(HashAlg::Sha256),
            Curve::P384 | Curve::BrainpoolP384r1 => Some(HashAlg::Sha384),
            Curve::P521 => Some(HashAlg::Sha512),
            Curve::Ed25519 | Curve::Ed448 => None,
        }
    }

    /// `msg` hashed with this hash.
    #[must_use]
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(msg).to_vec(),
            HashAlg::Sha384 => Sha384::digest(msg).to_vec(),
            HashAlg::Sha512 => Sha512::digest(msg).to_vec(),
        }
    }
}

/// How an ECDSA signature is encoded: raw `r ‖ s` (PKCS#11, TPM) or DER (X.509).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `r ‖ s`, each the curve's length: PKCS#11, TPM.
    Raw,
    /// An ASN.1 `Ecdsa-Sig-Value`: X.509.
    Der,
}

/// ECDSA over `msg` with the key in `spki` (P-256/384/521, secp256k1, brainpoolP256r1/P384r1),
/// hashed with `hash`, or with the curve's own hash when `None`. Either `s` is accepted:
/// secp256k1's verifier insists on the low one, so it is normalized first.
#[must_use]
pub fn ecdsa(spki: &[u8], msg: &[u8], sig: &[u8], encoding: Encoding, hash: Option<HashAlg>) -> Verdict {
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
            let digest = hash.unwrap_or($own).digest(msg);
            Some(checked(ecdsa::VerifyingKey::<$curve>::from(k).verify_prehash(&digest, &sig)))
        }};
    }
    // The curve the key's OIDs name (ISSUES.md Q20), the SPKI decoded once; any other key is no
    // ECDSA key.
    let (alg, info) = KeyAlg::read_spki(spki).ok()?;
    match alg {
        KeyAlg::Ec(Curve::P256) => curve!(p256::NistP256, HashAlg::Sha256, info),
        KeyAlg::Ec(Curve::P384) => curve!(p384::NistP384, HashAlg::Sha384, info),
        KeyAlg::Ec(Curve::P521) => curve!(p521::NistP521, HashAlg::Sha512, info),
        KeyAlg::Ec(Curve::Secp256k1) => curve!(k256::Secp256k1, HashAlg::Sha256, info),
        KeyAlg::Ec(Curve::BrainpoolP256r1) => curve!(bp256::BrainpoolP256r1, HashAlg::Sha256, info),
        KeyAlg::Ec(Curve::BrainpoolP384r1) => curve!(bp384::BrainpoolP384r1, HashAlg::Sha384, info),
        KeyAlg::Ec(Curve::Ed25519 | Curve::Ed448) | KeyAlg::Rsa => None,
    }
}

/// Pure Ed25519 over `msg` (strict verification).
#[must_use]
pub fn ed25519(spki: &[u8], msg: &[u8], sig: &[u8]) -> Verdict {
    let key = key_of::<ed25519_dalek::VerifyingKey>(spki, |a| a == KeyAlg::Ec(Curve::Ed25519))?;
    Some(key.and_then(|k| checked(ed25519_dalek::Signature::from_slice(sig).and_then(|s| k.verify_strict(msg, &s)))))
}

/// RSA PKCS#1 v1.5 over `msg` with the digest `D`. A key outside the 1024 to 8192 bits the `rsa`
/// crate computes with is [`Refused::Key`].
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

/// RSA-PSS over `msg` with the digest `D`, MGF1 of `D`, and a salt as long as `D`'s output (what
/// a proof asks the token for). A key the `rsa` crate does not compute with is [`Refused::Key`].
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

    /// One P-256 key signs the same message as raw `r ‖ s` and as DER: both verify, a flipped
    /// message does not, and a key of another kind answers `None`.
    #[test]
    fn ecdsa_encodings_and_kinds() {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use pkcs8::EncodePublicKey;
        let k = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let spki = k.verifying_key().to_public_key_der().unwrap();
        let s: Signature = k.sign_prehash(&HashAlg::Sha384.digest(b"m")).unwrap();
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

    /// `None` has one meaning: the SPKI names another kind of key (or is none). A key of the
    /// verifier's own kind that its parser refuses is `Some(Err(Key))`, with the parser's reason,
    /// for every verifier alike (review sig.rs F1).
    #[test]
    fn none_is_another_kind_and_a_refused_key_says_why() {
        use pkcs8::EncodePublicKey;
        // An SPKI whose OIDs name the kind, its key bytes refused by that kind's parser.
        let refused = |spki: &[u8]| {
            let mut bad = spki.to_vec();
            *bad.last_mut().unwrap() ^= 0x01;
            bad
        };
        let p256 =
            p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap().verifying_key().to_public_key_der().unwrap();
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_public_key_der().unwrap();
        // An Ed25519 SPKI holding 31 bytes, no Ed25519 key.
        let ed_short =
            [&[0x30, 0x29, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x20, 0x00][..], &[7; 31]].concat();
        // RSA-768: an RSA key the `rsa` crate does not compute with.
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
        // No SPKI, or one of another kind: `None` from each.
        for spki in [&b"no key"[..], ed.as_bytes()] {
            assert_eq!(ecdsa(spki, b"m", &sig, Encoding::Raw, None), None);
            assert_eq!(rsa_pkcs1v15::<Sha256>(spki, b"m", &sig), None);
            assert_eq!(rsa_pss::<Sha256>(spki, b"m", &sig), None);
        }
        assert_eq!(ed25519(p256.as_bytes(), b"m", &sig), None);
        assert_eq!(ed25519(&small, b"m", &sig), None);
    }
}
