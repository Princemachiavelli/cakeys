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
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Zeroizing<Vec<u8>>,
    pub prime_1: Zeroizing<Vec<u8>>,
    pub prime_2: Zeroizing<Vec<u8>>,
    pub exponent_1: Zeroizing<Vec<u8>>,
    pub exponent_2: Zeroizing<Vec<u8>>,
    pub coefficient: Zeroizing<Vec<u8>>,
}

/// Parse a PKCS#8 private key of `key_type` (and `curve`, for EC keys) into its parts.
///
/// # Errors
///
/// `Unsupported` for a key type or curve with no parser here; `Conflict` for bytes that are not
/// such a key (the message never includes them).
pub fn private_from_pkcs8(der: &[u8], key_type: KeyType, curve: Option<&str>) -> Result<PrivateParts> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let bad = |what: &str| KmError::Conflict(format!("the source's wrapped key is not a PKCS#8 {what} key"));
    let scalar = |bytes: &[u8]| Zeroizing::new(bytes.to_vec());
    match (key_type, curve.and_then(|c| Curve::from_cfg(key_type, c))) {
        (KeyType::Ec, Some(c)) => {
            let value = match c {
                Curve::P256 => scalar(&p256::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-256"))?.to_bytes()),
                Curve::P384 => scalar(&p384::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-384"))?.to_bytes()),
                Curve::P521 => scalar(&p521::SecretKey::from_pkcs8_der(der).map_err(|_| bad("P-521"))?.to_bytes()),
                Curve::Secp256k1 => {
                    scalar(&k256::SecretKey::from_pkcs8_der(der).map_err(|_| bad("secp256k1"))?.to_bytes())
                }
                Curve::BrainpoolP256r1 => {
                    scalar(&bp256::r1::SecretKey::from_pkcs8_der(der).map_err(|_| bad("brainpoolP256r1"))?.to_bytes())
                }
                Curve::BrainpoolP384r1 => {
                    scalar(&bp384::r1::SecretKey::from_pkcs8_der(der).map_err(|_| bad("brainpoolP384r1"))?.to_bytes())
                }
                Curve::Ed25519 | Curve::Ed448 => return Err(bad("EC")),
            };
            Ok(PrivateParts::Ec(value))
        }
        (KeyType::EcEdwards, Some(Curve::Ed25519)) => {
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(|_| bad("Ed25519"))?;
            Ok(PrivateParts::Edwards(Zeroizing::new(key.to_bytes().to_vec())))
        }
        (KeyType::Rsa, _) => rsa_parts(der).map(|p| PrivateParts::Rsa(Box::new(p))),
        (kt, _) => Err(KmError::Unsupported(format!(
            "no host-path parser for a {kt:?} private key{}",
            curve.map_or_else(String::new, |c| format!(" on {c}"))
        ))),
    }
}

/// The canonical SPKI of the public half of a PKCS#8 private key of any type cakeys parses (a
/// key file names no object: its identity, `rfc7093m4` of this, finds it in the lock).
///
/// # Errors
///
/// `Unsupported` for a key no parser here takes.
pub fn spki_of_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
    macro_rules! ec {
        ($key:ty) => {
            if let Ok(k) = <$key>::from_pkcs8_der(der) {
                return k.public_key().to_public_key_der().map(|d| d.as_bytes().to_vec()).map_err(spki_err);
            }
        };
    }
    ec!(p256::SecretKey);
    ec!(p384::SecretKey);
    ec!(p521::SecretKey);
    ec!(k256::SecretKey);
    ec!(bp256::r1::SecretKey);
    ec!(bp384::r1::SecretKey);
    if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        return k.verifying_key().to_public_key_der().map(|d| d.as_bytes().to_vec()).map_err(spki_err);
    }
    if let Ok(k) = rsa::PrivateKey::from_pkcs8_der(der) {
        return k.to_public_key().to_public_key_der().map(|d| d.as_bytes().to_vec()).map_err(spki_err);
    }
    Err(KmError::Unsupported("the key file holds no EC, Ed25519 or RSA private key cakeys reads".into()))
}

fn spki_err(e: impl std::fmt::Display) -> KmError {
    KmError::Unavailable(format!("encoding the public key: {e}"))
}

fn rsa_parts(der: &[u8]) -> Result<RsaParts> {
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
    let bad = || KmError::Conflict("the source's wrapped key is not a PKCS#8 RSA key".into());
    let mut key = rsa::PrivateKey::from_pkcs8_der(der).map_err(|_| bad())?;
    key.precompute().map_err(|_| bad())?;
    let be = |n: &rsa::BoxedUint| Zeroizing::new(n.to_be_bytes_trimmed_vartime().to_vec());
    let [p, q] = key.primes() else { return Err(bad()) };
    Ok(RsaParts {
        modulus: key.n().to_be_bytes_trimmed_vartime().to_vec(),
        public_exponent: key.e().to_be_bytes_trimmed_vartime().to_vec(),
        private_exponent: be(key.d()),
        prime_1: be(p),
        prime_2: be(q),
        exponent_1: be(key.dp().ok_or_else(bad)?),
        exponent_2: be(key.dq().ok_or_else(bad)?),
        coefficient: be(&key.crt_coefficient().ok_or_else(bad)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each parser takes what a key's own PKCS#8 encoder writes, and yields its private value.
    #[test]
    fn pkcs8_keys_parse_into_their_parts() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        use rsa::pkcs8::EncodePublicKey as _;
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
    }
}
