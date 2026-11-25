//! Object declarations: `[objects.<name>]` in keys.toml, their kinds and the
//! migration settings of a bundle (docs/CONFIG.md).

use super::{Deserialize, KeyType, KmError, ObjectClass, Result, Serialize};

/// An object's settings for camigrate (`[objects.<o>.migrate]`, docs/FILE.md): the file its
/// material is born in, for the pairs that say `origin = "file"`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectMigrateCfg {
    /// The file: a path, or `$NAME`/`${NAME}` read from the environment when camigrate reads it
    /// ([`Config::object_file`]), so hosts that only check load keys.toml without it.
    pub file: Option<String>,
    /// A file holding the passphrase of an encrypted key file (`$NAME` as for `file`).
    pub passphrase_file: Option<String>,
    /// An environment variable holding that passphrase; it wins over `passphraseFile`.
    pub passphrase_env: Option<String>,
    /// How a secret key's file spells its value; absent, its `valueLen` decides (docs/FILE.md F4).
    pub encoding: Option<Encoding>,
}

/// How a secret key's file spells its value (`migrate.encoding`): the bytes themselves, or hex
/// or base64 text of them, whitespace anywhere ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// The value's bytes, as they are.
    Raw,
    /// Hex digits, either case.
    Hex,
    /// Standard base64 (RFC 4648 §4), padded.
    Base64,
}

/// Intrinsic object type: identical across every spec of the object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectCfg {
    /// The object class (`CKO_*`).
    pub class: ObjectClass,
    /// For keys; absent for certificates and data objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    /// `CKC_*` for certificates (`CKC_X_509`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<String>,
    /// Canonical curve name after loading (`secp256r1`, not `P-256`), so an alias is never a
    /// different type or spec digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Secret key length in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_len: Option<u64>,
    /// RSA modulus size in bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus_bits: Option<u64>,
}

impl ObjectCfg {
    /// An object of `class` (and `key_type`) with no further type attributes.
    #[must_use]
    pub fn new(class: ObjectClass, key_type: Option<KeyType>) -> ObjectCfg {
        ObjectCfg { class, key_type, certificate_type: None, curve: None, value_len: None, modulus_bits: None }
    }

    /// Whether `other` is material of this type: every field equal, except that a `modulusBits`
    /// only one of them declares is no difference. The public key already fixes the modulus and
    /// the token check verifies a declared size, so declaring it later describes the same key;
    /// two different declared sizes are different material.
    #[must_use]
    pub fn same_type(&self, other: &ObjectCfg) -> bool {
        let bits = match (self.modulus_bits, other.modulus_bits) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        bits && ObjectCfg { modulus_bits: None, ..self.clone() } == ObjectCfg { modulus_bits: None, ..other.clone() }
    }

    /// Replace a curve alias by its canonical name (unknown names are left for validation), and
    /// fill in the length a key type fixes (`CKK_DES3`: 24) when `valueLen` is absent, so writing
    /// it or not is the same type, spec digest and commitment label.
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

    /// The curve of an EC or Edwards key (`curve`, for `keyType`).
    ///
    /// # Errors
    ///
    /// `Validation` when the object names no curve; `Unsupported` when the named curve has no
    /// `RustCrypto` crate to validate and encode it, or is not one of the supported ones.
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

    /// What the object is: its class and type fields parsed into one of the combinations
    /// cakeys manages ([`ObjectKind`]). Every object is parsed when keys.toml loads, used by a
    /// spec or not.
    ///
    /// # Errors
    ///
    /// `Validation` for a field that names nothing on this class or key type, a certificate
    /// without a `certificateType`, or one no PKCS#11 certificate type; `Unsupported` for what
    /// PKCS#11 has but cakeys does not manage: a class/key-type pairing, a certificate type
    /// other than `CKC_X_509`, or a curve [`Self::curve`] refuses.
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
        // A key's class and type pair first: a field that fits neither is the lesser news.
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

/// What an object is (`[objects.<name>]`, parsed by [`ObjectCfg::kind`]): each combination of
/// class, key type and type parameters cakeys manages is one variant, so a new parameter set
/// adds a variant rather than another optional field and its cross-field rules. keys.toml's
/// form and the spec digest stay [`ObjectCfg`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A private or a public key of an asymmetric type.
    Asymmetric {
        /// `CKO_PRIVATE_KEY` or `CKO_PUBLIC_KEY`.
        class: ObjectClass,
        /// The key's type and its parameters.
        key: AsymmetricKey,
    },
    /// A secret key: its type, and its length in bytes where keys.toml states it (a type with a
    /// fixed length has it filled in at load).
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

/// An asymmetric key's type and parameters ([`ObjectKind::Asymmetric`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricKey {
    /// `CKK_RSA`, with `modulusBits` where keys.toml states it (`create` needs it).
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

/// An object as parsed: keys.toml's form ([`ObjectCfg`], the type the lock pins and the spec
/// digest hashes) with what it is ([`ObjectKind`]). Made once where a target or a probe names
/// the object, so what reads its key type or curve after that cannot fail on them (review
/// 2026-11-23 A-8: every reader re-parsed the strings, with error arms load made unreachable).
/// Its fields read through to the [`ObjectCfg`].
#[derive(Debug, Clone, Copy)]
pub struct Object<'a> {
    pub(super) cfg: &'a ObjectCfg,
    kind: ObjectKind,
}

impl<'a> Object<'a> {
    /// `cfg`, parsed.
    ///
    /// # Errors
    ///
    /// Whatever [`ObjectCfg::kind`] refuses; never for an object of a loaded keys.toml.
    pub fn new(cfg: &'a ObjectCfg) -> Result<Object<'a>> {
        Ok(Object { cfg, kind: cfg.kind()? })
    }

    /// keys.toml's form.
    #[must_use]
    pub fn cfg(self) -> &'a ObjectCfg {
        self.cfg
    }

    /// What it is.
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
