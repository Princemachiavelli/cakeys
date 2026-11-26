//! The mapping of the core crate's object classes and key types to the classes and key types of
//! `cryptoki` (review 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// Returns the `cryptoki` class of a configured object.
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

/// Returns the configured class for a class that a token reports, or `None` when cakeys does not
/// manage that class.
pub(super) fn managed_class(class: ObjectClass) -> Option<Class> {
    Class::ALL.iter().copied().find(|c| class_of(&ObjectCfg::new(*c, None)) == class)
}

/// Returns the `cryptoki` key type of a key.
///
/// # Errors
///
/// `Unsupported` for an object that is not a key (a certificate or a data object), and for an
/// HMAC type that the binding cannot name (`hmac_key_type`).
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

/// Returns the generation mechanism of a hash-bound HMAC key type, which is the
/// `CKM_SHA*_KEY_GEN` mechanism of PKCS#11 3.0 for the type. `CKM_GENERIC_SECRET_KEY_GEN` makes
/// only `CKK_GENERIC_SECRET` keys, and `SoftHSM` and kryoptic refuse it for an HMAC type. Returns
/// `None` for any other key type. The function matches on the core crate's key type, because
/// cryptoki's constants for these types collide without the patch of the Nix build.
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

/// Returns the mechanism that generates a secret key of type `kt`. That is the type's own
/// `CKM_SHA*_KEY_GEN` for a hash-bound HMAC type ([`hmac_key_gen`]), `CKM_DES3_KEY_GEN` for DES3,
/// `CKM_AES_KEY_GEN` for AES, and `CKM_GENERIC_SECRET_KEY_GEN` otherwise. `create` runs this
/// mechanism, and the probe measures it.
#[must_use]
pub fn secret_key_gen(kt: Kt) -> Mechanism<'static> {
    hmac_key_gen(kt).unwrap_or(match kt {
        Kt::Aes => Mechanism::AesKeyGen,
        Kt::Des3 => Mechanism::Des3KeyGen,
        _ => Mechanism::GenericSecretKeyGen,
    })
}

/// Returns `kt` when it has the correct value `raw`, and refuses the key type otherwise. cryptoki
/// 0.12.1 (and its main branch) gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC`
/// (0x2b), so such keys could be neither created nor told apart. The Nix build patches this
/// (nix/patches/cryptoki-hmac-key-types.patch). Without the patch, the function refuses the key
/// type instead of misidentifying it. The error names the core crate's key type `name`, because
/// cryptoki's own name would be the name of the type that it collides with.
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
