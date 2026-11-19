//! Plaintext key material on the `host` path (docs/CAMIGRATE.md D2, phase 4): a private key as the
//! source's `C_WrapKey` hands it over (PKCS#8 `PrivateKeyInfo`), parsed into the parts a
//! target's `C_CreateObject` takes. Every secret part is zeroized when dropped; nothing here
//! formats, logs or returns a secret in an error.

use crate::id::Curve;
use crate::types::KeyType;
use crate::{KmError, Result};
use zeroize::Zeroizing;

/// A private key's parts, as PKCS#11 names them.
pub enum PrivateParts {
    /// A Weierstrass curve's private scalar (`CKA_VALUE`), big-endian, the curve's length.
    Ec(Zeroizing<Vec<u8>>),
    /// An Edwards private key (`CKA_VALUE`): the RFC 8410 seed.
    Edwards(Zeroizing<Vec<u8>>),
    /// An RSA private key.
    Rsa(Box<RsaParts>),
}

/// An RSA private key's parts, big-endian, as `CKA_MODULUS` … `CKA_COEFFICIENT`.
pub struct RsaParts {
    /// `CKA_MODULUS`.
    pub modulus: Vec<u8>,
    /// `CKA_PUBLIC_EXPONENT`.
    pub public_exponent: Vec<u8>,
    /// `CKA_PRIVATE_EXPONENT`.
    pub private_exponent: Zeroizing<Vec<u8>>,
    /// `CKA_PRIME_1`.
    pub prime_1: Zeroizing<Vec<u8>>,
    /// `CKA_PRIME_2`.
    pub prime_2: Zeroizing<Vec<u8>>,
    /// `CKA_EXPONENT_1`.
    pub exponent_1: Zeroizing<Vec<u8>>,
    /// `CKA_EXPONENT_2`.
    pub exponent_2: Zeroizing<Vec<u8>>,
    /// `CKA_COEFFICIENT`.
    pub coefficient: Zeroizing<Vec<u8>>,
}

/// A private scalar as its decoder hands it back, by value: that copy is wiped too.
fn scalar<B: AsRef<[u8]> + zeroize::Zeroize>(bytes: B) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(bytes);
    Zeroizing::new(bytes.as_ref().to_vec())
}

/// Parse a PKCS#8 private key of `key_type` (and `curve`, for EC keys) into its parts.
///
/// # Errors
///
/// `Unsupported` for a key type or curve with no parser here; `Conflict` for bytes that are not
/// such a key (the message never includes them).
pub fn private_from_pkcs8(der: &[u8], key_type: KeyType, curve: Option<&str>) -> Result<PrivateParts> {
    use pkcs8::DecodePrivateKey as _;
    let bad = |what: &str| KmError::Conflict(format!("the source's wrapped key is not a PKCS#8 {what} key").into());
    let ec = |value| Ok(PrivateParts::Ec(value));
    match (key_type, curve.and_then(|c| Curve::from_cfg(key_type, c))) {
        (KeyType::Ec, Some(Curve::P256)) => {
            ec(scalar(p256::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-256"))?.to_bytes()))
        }
        (KeyType::Ec, Some(Curve::P384)) => {
            ec(scalar(p384::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-384"))?.to_bytes()))
        }
        (KeyType::Ec, Some(Curve::P521)) => {
            ec(scalar(p521::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-521"))?.to_bytes()))
        }
        (KeyType::Ec, Some(Curve::Secp256k1)) => {
            ec(scalar(k256::SecretKey::from_pkcs8_der(der).map_err(|_| bad("secp256k1"))?.to_bytes()))
        }
        (KeyType::Ec, Some(Curve::BrainpoolP256r1)) => {
            ec(scalar(bp256::r1::SecretKey::from_pkcs8_der(der).map_err(|_| bad("brainpoolP256r1"))?.to_bytes()))
        }
        (KeyType::Ec, Some(Curve::BrainpoolP384r1)) => {
            ec(scalar(bp384::r1::SecretKey::from_pkcs8_der(der).map_err(|_| bad("brainpoolP384r1"))?.to_bytes()))
        }
        (KeyType::EcEdwards, Some(Curve::Ed25519)) => {
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(|_| bad("Ed25519"))?;
            Ok(PrivateParts::Edwards(scalar(key.to_bytes())))
        }
        (KeyType::Rsa, _) => rsa_parts(der).map(|p| PrivateParts::Rsa(Box::new(p))),
        (kt, _) => Err(KmError::Unsupported(
            format!(
                "no host-path parser for a {kt} private key{}",
                curve.map_or_else(String::new, |c| format!(" on {c}"))
            )
            .into(),
        )),
    }
}

/// The canonical SPKI of the public half of a PKCS#8 private key of any type cakeys parses (a
/// key file names no object: its identity, `rfc7093m4` of this, finds it in the lock).
///
/// # Errors
///
/// `Unsupported` for a key no parser here takes, or one its algorithm's own parser refuses
/// (ISSUES.md Q20: the parser is chosen by the key's OIDs).
pub fn spki_of_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    use crate::id::{Curve, KeyAlg};
    use pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
    let alg = KeyAlg::of_pkcs8(der).map_err(|e| {
        let said = e.into_msg().map_or_else(String::new, crate::Msg::into_text);
        KmError::Unsupported(format!("the key file's key: {said}").into())
    })?;
    let bad = |e: &dyn std::fmt::Display| {
        let what = match alg {
            KeyAlg::Ec(c) => c.display(),
            KeyAlg::Rsa => "RSA",
        };
        KmError::Unsupported(format!("the key file's {what} private key: {e}").into())
    };
    macro_rules! ec {
        ($key:ty) => {
            <$key>::from_pkcs8_der(der).map_err(|e| bad(&e))?.public_key().to_public_key_der()
        };
    }
    let spki = match alg {
        KeyAlg::Ec(Curve::P256) => ec!(p256::SecretKey),
        KeyAlg::Ec(Curve::P384) => ec!(p384::SecretKey),
        KeyAlg::Ec(Curve::P521) => ec!(p521::SecretKey),
        KeyAlg::Ec(Curve::Secp256k1) => ec!(k256::SecretKey),
        KeyAlg::Ec(Curve::BrainpoolP256r1) => ec!(bp256::r1::SecretKey),
        KeyAlg::Ec(Curve::BrainpoolP384r1) => ec!(bp384::r1::SecretKey),
        KeyAlg::Ec(Curve::Ed25519) => {
            ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(|e| bad(&e))?.verifying_key().to_public_key_der()
        }
        KeyAlg::Ec(Curve::Ed448) => return Err(bad(&"no Ed448 private key is read here")),
        KeyAlg::Rsa => rsa::PrivateKey::from_pkcs8_der(der).map_err(|e| bad(&e))?.to_public_key().to_public_key_der(),
    };
    spki.map(|d| d.as_bytes().to_vec()).map_err(spki_err)
}

/// A key that parsed whose public half does not encode: the key's fault, no token's (13).
fn spki_err(e: impl std::fmt::Display) -> KmError {
    KmError::Conflict(format!("encoding the public key: {e}").into())
}

/// A multi-prime RSA key (RFC 8017's `otherPrimeInfos`): PKCS#11 names two primes only.
fn multi_prime() -> KmError {
    KmError::Unsupported(
        "the source's wrapped key is a multi-prime RSA key, which has no PKCS#11 form (CKA_PRIME_1 and \
         CKA_PRIME_2 only)"
            .into(),
    )
}

/// Whether `der` is a PKCS#8 RSA key with more than two primes: what `rsa`'s decoder refuses
/// without saying why. Reads structure only, borrowing every part.
fn is_multi_prime(der: &[u8]) -> bool {
    use pkcs8::der::Decode as _;
    pkcs8::PrivateKeyInfoRef::from_der(der)
        .ok()
        .and_then(|info| rsa::pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).ok())
        .is_some_and(|k| k.version() == rsa::pkcs1::Version::Multi)
}

fn rsa_parts(der: &[u8]) -> Result<RsaParts> {
    use pkcs8::DecodePrivateKey as _;
    let bad = || KmError::Conflict("the source's wrapped key is not a PKCS#8 RSA key".into());
    let key =
        rsa::PrivateKey::from_pkcs8_der(der).map_err(|_| if is_multi_prime(der) { multi_prime() } else { bad() })?;
    rsa_key_parts(key)
}

/// The parts of a decoded RSA key: two primes, as PKCS#11 has them.
fn rsa_key_parts(mut key: rsa::PrivateKey) -> Result<RsaParts> {
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
    let bad = || KmError::Conflict("the source's wrapped key is not a PKCS#8 RSA key".into());
    if key.primes().len() != 2 {
        return Err(multi_prime());
    }
    key.precompute().map_err(|_| bad())?;
    // `into_vec` keeps the allocation: no second, unzeroized copy of a private part.
    let be = |n: &rsa::BoxedUint| Zeroizing::new(n.to_be_bytes_trimmed_vartime().into_vec());
    let [p, q] = key.primes() else { return Err(multi_prime()) };
    Ok(RsaParts {
        modulus: key.n().to_be_bytes_trimmed_vartime().to_vec(),
        public_exponent: key.e().to_be_bytes_trimmed_vartime().to_vec(),
        private_exponent: be(key.d()),
        prime_1: be(p),
        prime_2: be(q),
        exponent_1: be(key.dp().ok_or_else(bad)?),
        exponent_2: be(key.dq().ok_or_else(bad)?),
        // `crt_coefficient` computes an owned copy: wiped when dropped, like the key's own parts.
        coefficient: be(&Zeroizing::new(key.crt_coefficient().ok_or_else(bad)?)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each parser takes what a key's own PKCS#8 encoder writes, and yields its private value.
    #[test]
    fn pkcs8_keys_parse_into_their_parts() {
        use pkcs8::EncodePrivateKey as _;
        use pkcs8::EncodePublicKey as _;
        use rsa::traits::PublicKeyParts as _;
        let ec = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let der = ec.to_pkcs8_der().unwrap();
        let PrivateParts::Ec(v) = private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some("secp256r1")).unwrap() else {
            panic!("not EC")
        };
        assert_eq!(v.as_slice(), &[7u8; 32]);
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let der = ed.to_pkcs8_der().unwrap();
        let PrivateParts::Edwards(v) =
            private_from_pkcs8(der.as_bytes(), KeyType::EcEdwards, Some("edwards25519")).unwrap()
        else {
            panic!("not Edwards")
        };
        assert_eq!(v.as_slice(), &[9u8; 32]);
        let rsa = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let der = rsa.to_pkcs8_der().unwrap();
        let PrivateParts::Rsa(parts) = private_from_pkcs8(der.as_bytes(), KeyType::Rsa, None).unwrap() else {
            panic!("not RSA")
        };
        assert_eq!(parts.modulus, rsa.n().to_be_bytes_trimmed_vartime().to_vec());
        // A key file's public half, whatever its type: the SPKI the key's own encoder writes.
        assert_eq!(spki_of_pkcs8(der.as_bytes()).unwrap(), rsa.to_public_key().to_public_key_der().unwrap().as_bytes());
        let ec_der = ec.to_pkcs8_der().unwrap();
        assert_eq!(spki_of_pkcs8(ec_der.as_bytes()).unwrap(), ec.public_key().to_public_key_der().unwrap().as_bytes());
        // The wrong type, or bytes that are no key: refused, and never echoed.
        assert!(matches!(
            private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some("secp256r1")),
            Err(KmError::Conflict(_))
        ));
        assert!(
            matches!(private_from_pkcs8(&[1, 2, 3], KeyType::Rsa, None), Err(KmError::Conflict(m)) if !m.contains("010203"))
        );
        // A type with no parser is named as PKCS#11 names it.
        let e = private_from_pkcs8(der.as_bytes(), KeyType::Aes, None).err().unwrap();
        assert!(matches!(&e, KmError::Unsupported(m) if m.contains("a CKK_AES private key")), "{e}");
    }

    /// A multi-prime RSA key is an RSA key PKCS#11 has no attributes for: unsupported (15),
    /// saying so, never "not an RSA key" (13).
    #[test]
    fn a_multi_prime_rsa_key_is_unsupported() {
        use pkcs8::EncodePrivateKey as _;
        use pkcs8::der::{Decode as _, Encode as _, asn1::OctetStringRef};
        use rsa::pkcs1::{EncodeRsaPrivateKey as _, OtherPrimeInfo, RsaPrivateKeyRef, UintRef};
        let rsa = rsa::PrivateKey::new(&mut getrandom::SysRng, 1024).unwrap();
        let two = rsa.to_pkcs1_der().unwrap();
        let mut key = RsaPrivateKeyRef::from_der(two.as_bytes()).unwrap();
        let r = UintRef::new(&[7]).unwrap();
        key.other_prime_infos = Some(vec![OtherPrimeInfo { prime: r, exponent: r, coefficient: r }]);
        let pkcs1 = key.to_der().unwrap();
        let p8 = rsa.to_pkcs8_der().unwrap();
        let mut info = pkcs8::PrivateKeyInfoRef::from_der(p8.as_bytes()).unwrap();
        info.private_key = OctetStringRef::new(&pkcs1).unwrap();
        let three = info.to_der().unwrap();
        let e = private_from_pkcs8(&three, KeyType::Rsa, None).err().unwrap();
        assert!(matches!(&e, KmError::Unsupported(m) if m.contains("multi-prime RSA key")), "{e}");
        // Its two-prime original still parses.
        assert!(private_from_pkcs8(p8.as_bytes(), KeyType::Rsa, None).is_ok());
    }
}
