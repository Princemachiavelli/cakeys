//! The object declarations: `[objects.<name>]` in keys.toml, the kinds of objects, and the
//! migration settings of a bundle (docs/CONFIG.md).

use super::{Deserialize, KeyType, KmError, ObjectClass, Result, Serialize};

/// An object's settings for camigrate (`[objects.<o>.migrate]`, docs/FILE.md): the file from which
/// its material is created, for the pairs that have `origin = "file"`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectMigrateCfg {
    /// The file: a path, or `$NAME` or `${NAME}`, which is read from the environment when
    /// camigrate reads the file ([`Config::object_file`]). So hosts that only run checks can load
    /// keys.toml without the variable.
    ///
    /// [`Config::object_file`]: super::Config::object_file
    pub file: Option<String>,
    /// A file that holds the passphrase of an encrypted key file (`$NAME` works as for `file`).
    pub passphrase_file: Option<String>,
    /// An environment variable that holds that passphrase. It takes precedence over
    /// `passphraseFile`.
    pub passphrase_env: Option<String>,
    /// How a secret key's file encodes its value. When it is absent, the key's `valueLen` decides
    /// (docs/FILE.md F4).
    pub encoding: Option<Encoding>,
}

/// How a secret key's file encodes its value (`migrate.encoding`): the bytes themselves, or the
/// bytes as hex or base64 text. Whitespace is ignored everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// The value's bytes, unchanged.
    Raw,
    /// Hex digits, in upper or lower case.
    Hex,
    /// Standard base64 (RFC 4648 §4), padded.
    Base64,
}

/// The intrinsic object type, which is the same for every spec of the object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectCfg {
    /// The object class (`CKO_*`).
    pub class: ObjectClass,
    /// The key type, for keys. It is absent for certificates and data objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    /// The `CKC_*` certificate type, for certificates (`CKC_X_509`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<String>,
    /// The curve name, which is canonical after loading (`secp256r1`, not `P-256`), so that an
    /// alias never produces a different type or spec digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// The length of a secret key in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_len: Option<u64>,
    /// The size of an RSA modulus in bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus_bits: Option<u64>,
}

impl ObjectCfg {
    /// Returns an object type of `class` (and `key_type`) without further type attributes.
    #[must_use]
    pub fn new(class: ObjectClass, key_type: Option<KeyType>) -> ObjectCfg {
        ObjectCfg { class, key_type, certificate_type: None, curve: None, value_len: None, modulus_bits: None }
    }

    /// Returns whether `other` is material of this type. Every field must be equal, except that a
    /// `modulusBits` that only one of the two declares is not a difference. The public key already
    /// fixes the modulus, and the token check verifies a declared size, so a size that is declared
    /// later describes the same key. Two different declared sizes are different material.
    #[must_use]
    pub fn same_type(&self, other: &ObjectCfg) -> bool {
        let bits = match (self.modulus_bits, other.modulus_bits) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        bits && ObjectCfg { modulus_bits: None, ..self.clone() } == ObjectCfg { modulus_bits: None, ..other.clone() }
    }

    /// Replaces a curve alias with its canonical name (an unknown name is left for the
    /// validation), and fills in the length that a key type fixes (`CKK_DES3`: 24) when `valueLen`
    /// is absent. So the type, the spec digest and the commitment label are the same whether the
    /// length is written or not.
    pub fn canonicalize(&mut self) {
        if let Some(kt) = self.key_type
            && let Some(c) = self.curve.as_deref().and_then(|c| crate::id::Curve::from_cfg(kt, c))
        {
            self.curve = Some(c.name().to_owned());
        }
        if self.value_len.is_none() && self.class == ObjectClass::SecretKey {
            self.value_len = self.key_type.and_then(KeyType::fixed_value_len);
        }
    }

    /// Returns the curve of an EC or Edwards key (`curve`, for `keyType`).
    ///
    /// # Errors
    ///
    /// Returns `Validation` when the object names no curve. Returns `Unsupported` when no
    /// `RustCrypto` crate exists to validate and encode keys on the named curve, or when the curve
    /// is not one of the supported curves.
    pub fn curve(&self) -> Result<crate::id::Curve> {
        let kt = self.key_type.map_or("", KeyType::name);
        let name =
            self.curve.as_deref().ok_or_else(|| KmError::Validation(format!("{kt} keys need a curve").into()))?;
        self.key_type.and_then(|k| crate::id::Curve::from_cfg(k, name)).ok_or_else(|| {
            if crate::id::CURVES_WITHOUT_CRATE.contains(&name) {
                return KmError::Unsupported(
                    format!("curve {name:?}: no RustCrypto crate validates and encodes it yet").into(),
                );
            }
            KmError::Unsupported(
                format!(
                    "curve {name:?} for {kt} (supported: secp256r1, secp384r1, secp521r1, secp256k1, \
                 brainpoolP256r1, brainpoolP384r1 for CKK_EC; edwards25519, edwards448 for \
                 CKK_EC_EDWARDS)"
                )
                .into(),
            )
        })
    }

    /// Returns what the object is: its class and type fields parsed into one of the combinations
    /// that cakeys manages ([`ObjectKind`]). Every object is parsed when keys.toml loads, whether
    /// a spec uses it or not.
    ///
    /// # Errors
    ///
    /// Returns `Validation` for a field that has no meaning for this class or key type, for a
    /// certificate without a `certificateType`, or for a `certificateType` that is not a PKCS#11
    /// certificate type. Returns `Unsupported` for what PKCS#11 has but cakeys does not manage: a
    /// combination of class and key type, a certificate type other than `CKC_X_509`, or a curve
    /// that [`Self::curve`] refuses.
    pub fn kind(&self) -> Result<ObjectKind> {
        let invalid = |why: &str| Err(KmError::Validation(why.to_owned().into()));
        let class = self.class;
        let ecc = matches!(self.key_type, Some(KeyType::Ec | KeyType::EcEdwards));
        if self.certificate_type.is_some() && class != ObjectClass::Certificate {
            return invalid("certificateType applies to certificates only");
        }
        if self.key_type.is_some() && !class.is_key() {
            return invalid(if class == ObjectClass::Certificate {
                "certificates take no keyType"
            } else {
                "keyType applies to keys only"
            });
        }
        // The combination of a key's class and type is checked first, because it is the more
        // important error. A field that fits neither is reported only after it.
        if class.is_key() && self.key_type.is_none_or(|k| k.is_asymmetric() != class.is_asymmetric()) {
            return Err(KmError::Unsupported(format!("{class}/{}", self.key_type.map_or("", KeyType::name)).into()));
        }
        if self.curve.is_some() && !(ecc && class.is_asymmetric()) {
            return invalid("curve applies to CKK_EC and CKK_EC_EDWARDS keys only");
        }
        if self.modulus_bits.is_some() && !(self.key_type == Some(KeyType::Rsa) && class.is_asymmetric()) {
            return invalid("modulusBits applies to CKK_RSA keys only");
        }
        if self.value_len.is_some() && class != ObjectClass::SecretKey {
            return invalid("valueLen applies to secret keys only");
        }
        Ok(match (class, self.key_type) {
            (ObjectClass::Certificate, _) => match self.certificate_type.as_deref() {
                Some("CKC_X_509") => ObjectKind::Certificate,
                Some(t @ ("CKC_X_509_ATTR_CERT" | "CKC_WTLS" | "CKC_VENDOR_DEFINED")) => {
                    return Err(KmError::Unsupported(
                        format!("certificateType {t}: cakeys manages CKC_X_509 certificates only").into(),
                    ));
                }
                Some(t) => {
                    return invalid(&format!(
                        "certificateType {t:?} is no PKCS#11 certificate type (CKC_X_509, CKC_X_509_ATTR_CERT, \
                         CKC_WTLS, CKC_VENDOR_DEFINED)"
                    ));
                }
                None => return invalid("certificates need certificateType = \"CKC_X_509\""),
            },
            (ObjectClass::Data, _) => ObjectKind::Data,
            (c, Some(KeyType::Rsa)) if c.is_asymmetric() => {
                ObjectKind::Asymmetric { class: c, key: AsymmetricKey::Rsa { modulus_bits: self.modulus_bits } }
            }
            (c, Some(KeyType::Ec)) if c.is_asymmetric() => {
                ObjectKind::Asymmetric { class: c, key: AsymmetricKey::Ec(self.curve()?) }
            }
            (c, Some(KeyType::EcEdwards)) if c.is_asymmetric() => {
                ObjectKind::Asymmetric { class: c, key: AsymmetricKey::Edwards(self.curve()?) }
            }
            (ObjectClass::SecretKey, Some(k)) if !k.is_asymmetric() => {
                ObjectKind::Secret { key_type: k, value_len: self.value_len }
            }
            (c, k) => return Err(KmError::Unsupported(format!("{c}/{}", k.map_or("", KeyType::name)).into())),
        })
    }
}

/// What an object is (`[objects.<name>]`, parsed by [`ObjectCfg::kind`]). Each combination of
/// class, key type and type parameters that cakeys manages is one variant. So a new set of
/// parameters adds a variant, instead of another optional field with rules that relate it to
/// other fields. The form of keys.toml and the spec digest remain those of [`ObjectCfg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A private or a public key of an asymmetric type.
    Asymmetric {
        /// `CKO_PRIVATE_KEY` or `CKO_PUBLIC_KEY`.
        class: ObjectClass,
        /// The key's type and its parameters.
        key: AsymmetricKey,
    },
    /// A secret key: its type, and its length in bytes where keys.toml states it (the load fills
    /// in the length of a type with a fixed length).
    Secret {
        /// `CKK_AES`, an HMAC type, `CKK_GENERIC_SECRET`, `CKK_DES3`.
        key_type: KeyType,
        /// `valueLen`.
        value_len: Option<u64>,
    },
    /// An X.509 certificate.
    Certificate,
    /// A data object.
    Data,
}

/// The type and the parameters of an asymmetric key ([`ObjectKind::Asymmetric`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricKey {
    /// `CKK_RSA`, with `modulusBits` where keys.toml states it (`create` needs that value).
    Rsa {
        /// `modulusBits`.
        modulus_bits: Option<u64>,
    },
    /// `CKK_EC` on a supported Weierstrass curve.
    Ec(crate::id::Curve),
    /// `CKK_EC_EDWARDS` on a supported Edwards curve.
    Edwards(crate::id::Curve),
}

impl ObjectKind {
    /// The key type, for keys.
    #[must_use]
    pub fn key_type(self) -> Option<KeyType> {
        match self {
            ObjectKind::Asymmetric { key: AsymmetricKey::Rsa { .. }, .. } => Some(KeyType::Rsa),
            ObjectKind::Asymmetric { key: AsymmetricKey::Ec(_), .. } => Some(KeyType::Ec),
            ObjectKind::Asymmetric { key: AsymmetricKey::Edwards(_), .. } => Some(KeyType::EcEdwards),
            ObjectKind::Secret { key_type, .. } => Some(key_type),
            ObjectKind::Certificate | ObjectKind::Data => None,
        }
    }

    /// The curve, for EC and Edwards keys.
    #[must_use]
    pub fn curve(self) -> Option<crate::id::Curve> {
        match self {
            ObjectKind::Asymmetric { key: AsymmetricKey::Ec(c) | AsymmetricKey::Edwards(c), .. } => Some(c),
            _ => None,
        }
    }
}

/// A parsed object: the form in keys.toml ([`ObjectCfg`], which is the type that the lock pins
/// and that the spec digest hashes) together with what the object is ([`ObjectKind`]). It is
/// made once, where a target or a probe names the object, so that code that later reads the key
/// type or the curve cannot fail on them (review 2026-11-23 A-8: before, every reader parsed the
/// strings again, with error branches that the load made unreachable). Its fields are read
/// through to the [`ObjectCfg`].
#[derive(Debug, Clone, Copy)]
pub struct Object<'a> {
    pub(super) cfg: &'a ObjectCfg,
    kind: ObjectKind,
}

impl<'a> Object<'a> {
    /// Returns `cfg` parsed.
    ///
    /// # Errors
    ///
    /// Returns every error of [`ObjectCfg::kind`]. It never fails for an object of a keys.toml
    /// that loaded.
    pub fn new(cfg: &'a ObjectCfg) -> Result<Object<'a>> {
        Ok(Object { cfg, kind: cfg.kind()? })
    }

    /// Returns the form in keys.toml.
    #[must_use]
    pub fn cfg(self) -> &'a ObjectCfg {
        self.cfg
    }

    /// Returns what the object is.
    #[must_use]
    pub fn kind(self) -> ObjectKind {
        self.kind
    }

    /// The key type, for keys.
    #[must_use]
    pub fn key_type(self) -> Option<KeyType> {
        self.kind.key_type()
    }

    /// The curve, for EC and Edwards keys.
    #[must_use]
    pub fn curve(self) -> Option<crate::id::Curve> {
        self.kind.curve()
    }
}
