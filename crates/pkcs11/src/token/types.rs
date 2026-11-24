//! core's object classes and key types as `cryptoki`'s (review 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// The `cryptoki` class of a configured object.
#[must_use]
pub fn class_of(object: &ObjectCfg) -> ObjectClass {
    match object.class {
        Class::PrivateKey => ObjectClass::PRIVATE_KEY,
        Class::SecretKey => ObjectClass::SECRET_KEY,
        Class::PublicKey => ObjectClass::PUBLIC_KEY,
        Class::Certificate => ObjectClass::CERTIFICATE,
        Class::Data => ObjectClass::DATA,
    }
}

/// The configured class a token reports, if cakeys manages it.
pub(super) fn managed_class(class: ObjectClass) -> Option<Class> {
    Class::ALL.iter().copied().find(|c| class_of(&ObjectCfg::new(*c, None)) == class)
}

/// The `cryptoki` key type of a key.
///
/// # Errors
///
/// `Unsupported` for an object that is no key (a certificate, a data object), and for an HMAC
/// type the binding cannot name ([`hmac_key_type`]).
pub fn key_type_of(object: Object<'_>) -> Result<KeyType> {
    let kt =
        object.key_type().ok_or_else(|| KmError::Unsupported(format!("{} has no key type", object.class).into()))?;
    Ok(match kt {
        Kt::Ec => KeyType::EC,
        Kt::EcEdwards => KeyType::EC_EDWARDS,
        Kt::Rsa => KeyType::RSA,
        Kt::GenericSecret => KeyType::GENERIC_SECRET,
        Kt::Aes => KeyType::AES,
        Kt::Des3 => KeyType::DES3,
        Kt::Sha1Hmac => KeyType::SHA_1_HMAC,
        kt @ Kt::Sha224Hmac => hmac_key_type(kt, KeyType::SHA224_HMAC, 0x2e)?,
        Kt::Sha256Hmac => KeyType::SHA256_HMAC,
        kt @ Kt::Sha384Hmac => hmac_key_type(kt, KeyType::SHA384_HMAC, 0x2c)?,
        kt @ Kt::Sha512Hmac => hmac_key_type(kt, KeyType::SHA512_HMAC, 0x2d)?,
    })
}

/// The generation of a hash-bound HMAC key type: PKCS#11 3.0's `CKM_SHA*_KEY_GEN` for the type
/// (`CKM_GENERIC_SECRET_KEY_GEN` makes `CKK_GENERIC_SECRET` keys only; `SoftHSM` and kryoptic
/// refuse it for an HMAC type). `None` for any other key type. By core's key type: cryptoki's
/// constants for these types collide without the Nix build's patch.
#[must_use]
pub fn hmac_key_gen(kt: Kt) -> Option<Mechanism<'static>> {
    Some(match kt {
        Kt::Sha1Hmac => Mechanism::Sha1KeyGen,
        Kt::Sha224Hmac => Mechanism::Sha224KeyGen,
        Kt::Sha256Hmac => Mechanism::Sha256KeyGen,
        Kt::Sha384Hmac => Mechanism::Sha384KeyGen,
        Kt::Sha512Hmac => Mechanism::Sha512KeyGen,
        _ => return None,
    })
}

/// The mechanism that generates a secret key of type `kt`: its own `CKM_SHA*_KEY_GEN` for a
/// hash-bound HMAC type ([`hmac_key_gen`]), `CKM_DES3_KEY_GEN`, `CKM_AES_KEY_GEN`, else
/// `CKM_GENERIC_SECRET_KEY_GEN`. What `create` runs and the probe measures.
#[must_use]
pub fn secret_key_gen(kt: Kt) -> Mechanism<'static> {
    hmac_key_gen(kt).unwrap_or(match kt {
        Kt::Aes => Mechanism::AesKeyGen,
        Kt::Des3 => Mechanism::Des3KeyGen,
        _ => Mechanism::GenericSecretKeyGen,
    })
}

/// cryptoki 0.12.1 (and main) gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC` (0x2b), so such
/// keys could be neither created nor told apart. The Nix build patches it
/// (nix/patches/cryptoki-hmac-key-types.patch); refuse rather than misidentify without the patch.
/// Named by core's key type `name`: cryptoki's own names the type it collides with.
pub(super) fn hmac_key_type(name: Kt, kt: KeyType, raw: std::os::raw::c_ulong) -> Result<KeyType> {
    if std::os::raw::c_ulong::from(kt) == raw {
        Ok(kt)
    } else {
        Err(KmError::Unsupported(
            format!(
                "{name}: this build's cryptoki maps it to CKK_SHA256_HMAC; build with \
             nix/patches/cryptoki-hmac-key-types.patch applied"
            )
            .into(),
        ))
    }
}
