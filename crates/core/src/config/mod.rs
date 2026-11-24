//! `keys.toml` (input) and `keys.lock` (input, updated in place).
//!
//! Our own keys are camelCase (Nix-friendly); PKCS#11 names (`CKA_*`, `CKO_*`, `CKK_*`) are verbatim.

use crate::error::{KmError, Result};
use crate::types::{KeyType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod io;
mod lock;
mod observe;
pub use io::*;
pub use lock::*;
pub use observe::*;

/// A parsed `keys.toml` (docs/CONFIG.md): the tokens, the objects, and the specs that realise
/// objects on tokens.
#[derive(Debug, Default, Deserialize)]
#[serde(from = "RawConfig")]
pub struct Config {
    /// The PKCS#11 tokens, by name (`[tokens.<name>]`).
    pub tokens: BTreeMap<String, TokenCfg>,
    /// The objects, by name (`[objects.<name>]`): each one's intrinsic type.
    pub objects: BTreeMap<String, ObjectCfg>,
    /// What only camigrate reads of an object (`[objects.<o>.migrate]`), by object name: kept
    /// apart from [`ObjectCfg`], which is the type the lock pins, so a per-machine path is never
    /// part of it. Objects without the table have no entry.
    pub object_migrate: BTreeMap<String, ObjectMigrateCfg>,
    /// The specs, by name (`[specs.<name>]`): an object's policy and the tokens it is realised on.
    pub specs: BTreeMap<String, SpecCfg>,
    /// Directories of module profiles to load beside the ones this build embeds
    /// (docs/CAPROBE.md): a new vendor's profile, and with it its provider by family name,
    /// without a rebuild. They only add: one may not replace an embedded profile, a layer or the
    /// baseline. `$NAME` references read the environment, as for `pinFile`.
    pub profile_dirs: Vec<PathBuf>,
}

/// keys.toml as written: [`Config`] before an object's `migrate` table is split from its type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    tokens: BTreeMap<String, TokenCfg>,
    #[serde(default)]
    objects: BTreeMap<String, ObjectEntry>,
    #[serde(default)]
    specs: BTreeMap<String, SpecCfg>,
    #[serde(default, rename = "profileDirs")]
    profile_dirs: Vec<PathBuf>,
}

/// One `[objects.<name>]` table: the object's type ([`ObjectCfg`]'s fields) and its `migrate`
/// table. The fields are spelled out rather than flattened: serde's `flatten` would lose
/// `deny_unknown_fields`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObjectEntry {
    class: ObjectClass,
    #[serde(default)]
    key_type: Option<KeyType>,
    #[serde(default)]
    certificate_type: Option<String>,
    #[serde(default)]
    curve: Option<String>,
    #[serde(default)]
    value_len: Option<u64>,
    #[serde(default)]
    modulus_bits: Option<u64>,
    #[serde(default)]
    migrate: Option<ObjectMigrateCfg>,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Config {
        let mut objects = BTreeMap::new();
        let mut object_migrate = BTreeMap::new();
        for (name, o) in raw.objects {
            if let Some(m) = o.migrate {
                object_migrate.insert(name.clone(), m);
            }
            let ObjectEntry { class, key_type, certificate_type, curve, value_len, modulus_bits, .. } = o;
            objects.insert(name, ObjectCfg { class, key_type, certificate_type, curve, value_len, modulus_bits });
        }
        Config { tokens: raw.tokens, objects, object_migrate, specs: raw.specs, profile_dirs: raw.profile_dirs }
    }
}

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

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Encoding::Raw => "raw",
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
        })
    }
}

/// One token (`[tokens.<name>]`): the module that reaches it, its label and credentials, and what
/// its provider needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenCfg {
    /// The PKCS#11 module: a path, or `$NAME`/`${NAME}` read from the environment when the token
    /// is opened ([`TokenCfg::module_path`]). It is per machine, so it may be left out and given
    /// per run with `--module <token>=<path>` (what `lib.mkKeys`'s `modules.<token>` passes), which
    /// replaces it unexpanded. A bare file name is the dynamic loader's library search
    /// (`LD_LIBRARY_PATH`; on NixOS nothing else). The lock records the file actually loaded and
    /// its hash, as provenance only.
    pub module: Option<String>,
    /// Provider crate, or module profile family, handling this module's quirks; auto-detected
    /// from `C_GetInfo` if unset. A family, never one profile ([`Self::module_profile`]).
    pub provider: Option<String>,
    /// One module profile by its full name (`aws-cloudhsm/5.18+hsm2m-non-fips`), for profiles
    /// that tie on every match key (PKCS#11 reports no FIPS mode, docs/CAPROBE.md D12). Its
    /// family is the provider when `provider` is unset. Not `profiles`, which are delta layers.
    #[serde(default)]
    pub module_profile: Option<String>,
    /// Delta capability layers to compose over the module profile (docs/CAPROBE.md), by name
    /// or family: the hardware under the module (`swtpm`), or anything else between cakeys
    /// and it. The cryptoki binding layer is always applied; p11-kit is detected from the
    /// module itself. Unknown names refuse (17).
    #[serde(default)]
    pub profiles: Vec<String>,
    /// The label the token reports (`CK_TOKEN_INFO.label`): which of the module's tokens this is.
    pub token_label: String,
    /// The serial number the token reports (`CK_TOKEN_INFO.serialNumber`), when two of the
    /// module's tokens carry one label: with it, only the token with both matches.
    #[serde(default)]
    pub token_serial: Option<String>,
    /// A file holding the user PIN (`$NAME` reads the path from the environment when the PIN is
    /// read: [`Self::pin_path`]). With neither it nor `pinEnv`, the token is used without
    /// logging in.
    pub pin_file: Option<PathBuf>,
    /// An environment variable holding the user PIN; it wins over `pinFile`.
    pub pin_env: Option<String>,
    /// The Security Officer credential, for modules that create and destroy objects only in an
    /// SO session — ykcs11: the PIV management key in hex, or the PIN on a device whose
    /// management key is PIN-protected; elsewhere the SO PIN (camigrate's `transport --trusted`).
    /// `pinFile`/`pinEnv` remain the *user* credential. Read just before such a step, never by
    /// `resolve` or `check`; the user session is restored afterwards, so a user PIN is
    /// required. `soCredentialEnv` wins if both are set; `soCredentialFile` may be `$NAME`, like
    /// `pinFile`. Refused on a provider that does not need it.
    pub so_credential_file: Option<PathBuf>,
    /// An environment variable holding the SO credential; it wins over `soCredentialFile`.
    pub so_credential_env: Option<String>,
    /// Settings only the token's provider understands, as `[tokens.<t>.options]` (tpm2-pkcs11:
    /// `tcti`, `tpm2Store`, `akHandle`). The provider checks them when the token is opened, and
    /// one that takes none refuses any (17).
    #[serde(default)]
    pub options: Options,
    /// What only caprobe reads (`[tokens.<t>.probe]`).
    #[serde(default)]
    pub probe: ProbeCfg,
    /// What only camigrate reads (`[tokens.<t>.migrate]`).
    #[serde(default)]
    pub migrate: TokenMigrateCfg,
    /// What only the Nix library reads (`[tokens.<t>.nix]`).
    #[serde(default)]
    pub nix: NixCfg,
}

/// A token's settings for caprobe (`[tokens.<t>.probe]`, docs/CAPROBE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProbeCfg {
    /// Marks the token as expendable: its write probes generate, wrap, unwrap and destroy
    /// objects, so `probe --write-probes` runs them only here and is refused (17) on any other token.
    #[serde(default)]
    pub scratch: bool,
    /// The one `CKA_ID` (hex) the write probes may generate into, on a token whose module
    /// creates only as Security Officer into fixed device slots named by `CKA_ID` (ykcs11): such
    /// a token holds real keys beside the scratch slot, so `scratch` cannot mark all of it. Each
    /// probe generation replaces the slot's key, and what the last one generated stays (PIV
    /// cannot erase a key). The probe still refuses a slot holding anything but its provider's
    /// own placeholder (`Provider::scratch_occupant`).
    pub scratch_id: Option<String>,
}

/// A token's settings for camigrate (`[tokens.<t>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenMigrateCfg {
    /// The spec of this token's transport key (D3): an RSA private key realised here that may
    /// unwrap and never leaves the token. Sealed moves to this token wrap to it, never to one
    /// picked by what it can do (camigrate `--transport-spec` overrides it per run); its
    /// realisation records the public key in the lock, so any host can export to it. It never
    /// leaves the tokens its spec realises it on, as if `migrate.noExport` (camigrate refuses it
    /// named, 15, and leaves it out without names).
    pub transport_with: Option<String>,
}

/// A token's settings for the Nix library (`[tokens.<t>.nix]`, docs/CAKEYS.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NixCfg {
    /// The `requiredSystemFeatures` entry: defaults to `<featurePrefix><name>` (`lib.mkKeys`'s
    /// `featurePrefix`, default `token-`). The NixOS module advertises `<featurePrefix><n>` for
    /// each of its tokens, so this names one of those.
    pub system_feature: Option<String>,
}

/// A token's provider-specific settings (`[tokens.<t>.options]`), parsed by the provider.
pub type Options = toml::Table;

impl TokenCfg {
    /// A token labelled `token_label` with nothing else set: what a keys.toml entry naming only
    /// `tokenLabel` parses to.
    #[must_use]
    pub fn labelled(token_label: String) -> TokenCfg {
        TokenCfg {
            module: None,
            provider: None,
            module_profile: None,
            profiles: Vec::new(),
            token_label,
            token_serial: None,
            pin_file: None,
            pin_env: None,
            so_credential_file: None,
            so_credential_env: None,
            options: Options::new(),
            probe: ProbeCfg::default(),
            migrate: TokenMigrateCfg::default(),
            nix: NixCfg::default(),
        }
    }

    /// The provider keys.toml names: `provider`, else the family of `moduleProfile`
    /// (`aws-cloudhsm` for `aws-cloudhsm/5.18+hsm2m-non-fips`). `None`: detect it.
    #[must_use]
    pub fn named_provider(&self) -> Option<&str> {
        self.provider
            .as_deref()
            .or_else(|| self.module_profile.as_deref().map(|p| p.split_once('/').map_or(p, |(family, _)| family)))
    }

    /// The module to load, its `$NAME` reference resolved by `env` now: resolved when the token
    /// is opened, so an unset one fails only a run that uses this token without `--module`.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `module` names an unset variable.
    pub fn module_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<String>> {
        self.module.as_deref().map(|m| env_ref(m, &format!("token '{token}': module"), env)).transpose()
    }

    /// The file holding the user PIN (`pinFile`), its `$NAME` reference resolved by `env` now:
    /// resolved when the PIN is read, so an unset variable fails only a run that logs in to this
    /// token. `None` when keys.toml names no file.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `pinFile` names an unset variable; `Validation` (17) for a file in
    /// the Nix store.
    pub fn pin_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.pin_file.as_deref(), &format!("token '{token}': pinFile"), env)
    }

    /// The file holding the admin credential (`soCredentialFile`), resolved as [`Self::pin_path`].
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `soCredentialFile` names an unset variable; `Validation` (17) for
    /// a file in the Nix store.
    pub fn so_credential_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.so_credential_file.as_deref(), &format!("token '{token}': soCredentialFile"), env)
    }
}

/// A secret file's path with its `$NAME` reference resolved, and refused when that is in the
/// world-readable Nix store ([`secret_in_store`]): what load could not see of a `$NAME` path.
fn secret_path(path: Option<&Path>, what: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
    let Some(path) = path else { return Ok(None) };
    let path = PathBuf::from(env_ref(&path.to_string_lossy(), what, env)?);
    match secret_in_store(&what, &path) {
        Some(why) => Err(KmError::Validation(why.into())),
        None => Ok(Some(path)),
    }
}

/// Parse a token's `options` into the provider's own settings type, which should deny unknown
/// fields: a typo is invalid (17), naming the token.
///
/// # Errors
///
/// `Validation` if the table does not fit `T`: an unknown option name or a bad value.
pub fn parse_options<T: serde::de::DeserializeOwned>(token: &str, options: &Options) -> Result<T> {
    options.clone().try_into().map_err(|e| KmError::Validation(format!("tokens.{token}.options: {e}").into()))
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

    /// The key type, if this class can have it (and, for EC and Edwards keys, a supported curve);
    /// any other pairing is unsupported (15).
    ///
    /// # Errors
    ///
    /// `Unsupported` for a class/key-type pairing cakeys does not manage, and whatever `curve`
    /// rejects for EC and Edwards keys (`Validation` when the object names no curve).
    pub fn checked_key_type(&self) -> Result<KeyType> {
        self.kind()?.key_type().ok_or_else(|| {
            KmError::Unsupported(format!("{}/{}", self.class, self.key_type.map_or("", KeyType::name)).into())
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
}

/// Inline-table form, as keys.toml writes it.
impl std::fmt::Display for ObjectCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![format!("class = \"{}\"", self.class)];
        fields.extend(self.key_type.map(|k| format!("keyType = \"{k}\"")));
        fields.extend(self.certificate_type.as_ref().map(|c| format!("certificateType = {c:?}")));
        fields.extend(self.curve.as_ref().map(|c| format!("curve = {c:?}")));
        fields.extend(self.value_len.map(|n| format!("valueLen = {n}")));
        fields.extend(self.modulus_bits.map(|n| format!("modulusBits = {n}")));
        write!(f, "{{ {} }}", fields.join(", "))
    }
}

/// A spec's settings for camigrate (`[specs.<s>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecMigrateCfg {
    /// The object never leaves the tokens this spec realises it on: `camigrate` refuses to
    /// export or migrate it from them (15), and an export or migrate without names leaves it out
    /// without the warning a key that cannot move gets. A token's transport key
    /// (`transportWith`) is kept so without it.
    #[serde(default)]
    pub no_export: bool,
}

/// A spec (`[specs.<name>]`): the policy one object is realised with, and the tokens it is
/// realised on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCfg {
    /// The object (`[objects.<name>]`) this spec realises.
    pub object: String,
    /// Policy attributes of the object (`CKA_SIGN = true`, `CKA_ALLOWED_MECHANISMS = [...]`).
    /// Part of the spec digest.
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrValue>,
    /// Policy attributes of a private key's public key object (`CKA_VERIFY = true`, ...): set
    /// when generating, checked on the public object. In the spec digest only when present.
    #[serde(default, rename = "publicAttributes")]
    pub public_attributes: BTreeMap<String, AttrValue>,
    /// What only camigrate reads (`[specs.<s>.migrate]`). Not in the spec digest.
    #[serde(default)]
    pub migrate: SpecMigrateCfg,
    /// The tokens this spec realises the object on, by token name.
    pub tokens: BTreeMap<String, SpecTokenCfg>,
}

impl SpecCfg {
    /// A declared boolean attribute.
    #[must_use]
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.attributes.get(name) {
            Some(AttrValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// The declared `CKA_ALLOWED_MECHANISMS`, if any: the mechanisms the key may run.
    #[must_use]
    pub fn allowed_mechanisms(&self) -> Option<&[String]> {
        match self.attributes.get(crate::attrs::ALLOWED_MECHANISMS) {
            Some(AttrValue::Mechanisms(m)) => Some(m),
            _ => None,
        }
    }
}

/// A policy attribute value: a boolean, or a set of `CKM_*` names (`CKA_ALLOWED_MECHANISMS`),
/// kept sorted and without duplicates so its order never changes a digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AttrValue {
    /// A boolean attribute (`CKA_SIGN = true`).
    Bool(bool),
    /// A mechanism set (`CKA_ALLOWED_MECHANISMS`), sorted and without duplicates.
    Mechanisms(Vec<String>),
}

impl AttrValue {
    /// A mechanism set from `names` in any order: sorted, duplicates dropped.
    pub fn mechanisms(names: impl IntoIterator<Item = String>) -> AttrValue {
        let set: BTreeSet<String> = names.into_iter().collect();
        AttrValue::Mechanisms(set.into_iter().collect())
    }
}

impl std::fmt::Display for AttrValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttrValue::Bool(b) => write!(f, "{b}"),
            AttrValue::Mechanisms(m) => write!(f, "[{}]", m.join(", ")),
        }
    }
}

/// One token of a spec (`[specs.<s>.tokens.<t>]`): where the object is found there and how it
/// is held.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecTokenCfg {
    /// The `CKA_LABEL` and `CKA_ID` the object is found under on this token.
    pub locator: Locator,
    /// How the object comes to be on this token ([`KeyOrigin`]). Required for a private or
    /// secret key; anything else is adopted unless it says `import`. Use [`Self::key_origin`].
    #[serde(default)]
    pub origin: Option<KeyOrigin>,
    /// Adopt a private key through its public key object only (no login needed, e.g. to
    /// spare PIV PIN retries). Identity is fully verified; presence and policy of the private
    /// half are not, so this is an explicit per-token opt-in recorded in the lock.
    #[serde(default)]
    pub public_only: bool,
    /// `"token-asserted"`: do not prove possession of the private key, for keys that cannot sign
    /// anything the host can verify. Recorded in the lock; `publicOnly` implies it.
    #[serde(default)]
    pub binding: Option<Binding>,
    /// Opt in to the attestation commitment (§3.7 of docs/DESIGN.md): compute the provider's
    /// attestation scheme for this key on this token (`YubiKey` PIV attestation verified to the
    /// pinned Yubico root; a native `TPM2_Certify` for tpm2-pkcs11) and require it ever after —
    /// a realisation that stops computing it is a scheme downgrade (exit 14). The attestation
    /// ID never replaces the portable one: it is recorded only beside `rfc7093m4` (keys) or a
    /// commitment scheme (secret keys), which is what verifies the same material copied to
    /// another token, where no attestation can exist.
    #[serde(default)]
    pub attestation: bool,
}

impl SpecTokenCfg {
    /// The object's origin on this token: as keys.toml says it, else `adopt` (what load allows
    /// to leave it out: anything but an unadopted private or secret key).
    #[must_use]
    pub fn key_origin(&self) -> KeyOrigin {
        self.origin.unwrap_or(KeyOrigin::Adopt)
    }
}

/// How an object comes to be on a token (`tokens.<t>.origin`, docs/CONFIG.md): which verb, if
/// any, puts it there. Not part of the spec digest: like the locator, it says where, not what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyOrigin {
    /// `cakeys create` generates it here: at most one pair per object, which is where the
    /// material is born and whose policy it is born with.
    Create,
    /// camigrate brings the material here from another token; it is never generated here.
    Import,
    /// It is already here, put there by something cakeys does not run; nothing writes it.
    Adopt,
    /// camigrate brings it here from the file its object's `migrate.file` names, where the
    /// material is born (docs/FILE.md). Several pairs may say it: they all read that one file.
    File,
}

impl KeyOrigin {
    /// The name keys.toml writes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            KeyOrigin::Create => "create",
            KeyOrigin::Import => "import",
            KeyOrigin::Adopt => "adopt",
            KeyOrigin::File => "file",
        }
    }
}

impl std::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Arbitrary user values naming the object on one token. Not part of the spec digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    /// The object's `CKA_LABEL`.
    #[serde(rename = "CKA_LABEL", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Hex-encoded.
    #[serde(rename = "CKA_ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl Locator {
    /// Refuse a locator no search can use, and write its `CKA_ID` in lower case so `0A` and `0a`
    /// name one object. An empty `CKA_ID` is a real object's ID, and stays.
    ///
    /// # Errors
    ///
    /// Why, when it names neither `CKA_LABEL` nor `CKA_ID`, or its `CKA_ID` is not hex.
    pub fn canonicalize(&mut self) -> std::result::Result<(), String> {
        if self.label.is_none() && self.id.is_none() {
            return Err("locator needs CKA_LABEL and/or CKA_ID".into());
        }
        if let Some(id) = &mut self.id {
            if crate::hex::decode(id).is_none() {
                return Err(format!("CKA_ID '{id}' is not hex"));
            }
            id.make_ascii_lowercase();
        }
        Ok(())
    }
}

/// Inline-table form, as keys.toml writes it: `{ CKA_LABEL = "k", CKA_ID = "01" }`.
impl std::fmt::Display for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::new();
        if let Some(l) = &self.label {
            fields.push(format!("CKA_LABEL = {l:?}"));
        }
        if let Some(i) = &self.id {
            fields.push(format!("CKA_ID = {i:?}"));
        }
        write!(f, "{{ {} }}", fields.join(", "))
    }
}

/// Identity modes, strongest first (docs/DESIGN.md §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// The ID hashes the object's public material: public keys, certificates, data objects.
    Direct,
    /// The ID hashes a commitment the token computes with the secret key (a MAC, a check value, a
    /// wrap), for secret keys whose usage bits allow one.
    Commitment,
    /// An extractable secret key without such bits: wrapped under a session KEK, unwrapped as a
    /// session copy that allows every scheme of its type, committed, then both destroyed.
    WrapRebind,
}

/// How a private-key object is bound to the public key its identity hashes (docs/DESIGN.md §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Binding {
    /// The token signed a fresh challenge that verified on the host against that public key.
    PopSign,
    /// `pop-sign` on a `CKA_ALWAYS_AUTHENTICATE` key: the same proof, with the per-use
    /// `C_Login(CKU_CONTEXT_SPECIFIC)` the key demands before it signs. Derived from the
    /// observed attribute and recorded in the lock; never written in keys.toml.
    PopSignPin,
    /// The token derived the ECDH shared secret with an ephemeral host key and both sides `MACed`
    /// the challenge with it (derive-only EC keys).
    PopEcdh,
    /// The token decrypted a host challenge (RSA-OAEP) to the expected plaintext (decrypt-only
    /// RSA keys).
    PopDecrypt,
    /// The token unwrapped a host secret (RSA-OAEP) into a non-extractable session key and both
    /// sides `MACed` the challenge with it (unwrap-only RSA keys: transport keys, docs/CAMIGRATE.md D3).
    PopUnwrap,
    /// Only the token says the objects belong together (opt-in, or `publicOnly`).
    TokenAsserted,
}

impl Binding {
    /// Strength, strongest 0: a realisation must never move to a higher rank. Every `pop-*`
    /// proves the same fact — possession of the named public key — by whichever capability the
    /// key has. `pop-sign-pin` proves it too: its per-use PIN is recorded by the observed
    /// `CKA_ALWAYS_AUTHENTICATE` bit in the policy, not by a weaker rank.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Binding::PopSign | Binding::PopSignPin | Binding::PopEcdh | Binding::PopDecrypt | Binding::PopUnwrap => 0,
            Binding::TokenAsserted => 1,
        }
    }

    /// The name keys.toml and the lock write.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Binding::PopSign => "pop-sign",
            Binding::PopSignPin => "pop-sign-pin",
            Binding::PopEcdh => "pop-ecdh",
            Binding::PopDecrypt => "pop-decrypt",
            Binding::PopUnwrap => "pop-unwrap",
            Binding::TokenAsserted => "token-asserted",
        }
    }

    /// The proof a capability row names (`prove.<proof>.…`, docs/CAPROBE.md): the binding's,
    /// `pop-sign` for a per-use PIN too; `None` for `token-asserted`, which proves nothing.
    #[must_use]
    pub fn proof_name(self) -> Option<&'static str> {
        match self {
            Binding::PopSignPin => Some(Binding::PopSign.name()),
            Binding::TokenAsserted => None,
            proven => Some(proven.name()),
        }
    }
}

impl std::fmt::Display for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Mode {
    /// Strength, strongest 0: a realisation must never move to a higher rank.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Mode::Direct => 0,
            Mode::Commitment => 1,
            Mode::WrapRebind => 2,
        }
    }

    /// The name the lock writes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Commitment => "commitment",
            Mode::WrapRebind => "wrap-rebind",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Read and check keys.toml; `$NAME` path references read the process environment.
///
/// # Errors
///
/// Whatever [`load_config_with`] rejects: `Io` if the file cannot be read; `Validation` for
/// a schema violation, a malformed or unset `$NAME` path reference, an admin credential
/// without a user PIN to return to, or a spec that references an unknown object.
pub fn load_config(path: &Path) -> Result<Config> {
    load_config_with(path, &|name| std::env::var(name).ok())
}

/// [`load_config`], with `env` looking up the variables `$NAME` path references name.
///
/// # Errors
///
/// `Io` if the file cannot be read; `Validation` for a schema violation, a malformed or unset
/// `$NAME` path reference, an admin credential without a user PIN to return to, or a spec that
/// references an object keys.toml does not define.
pub fn load_config_with(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let text = std::fs::read_to_string(path).map_err(KmError::io(format_args!("reading {}", path.display())))?;
    parse_config_with(&text, path, env)
}

/// [`load_config_with`] on text already read; `path` only names it in messages.
///
/// # Errors
///
/// `Validation`, as [`load_config_with`].
pub fn parse_config_with(text: &str, path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let invalid = |e: &dyn std::fmt::Display| KmError::Validation(format!("{}: {e}", path.display()).into());
    // A `$NAME` reference's error, named by the file as every other load error is: one resolved
    // at load is keys.toml's own, so unset is invalid here (17).
    let env_ref = |value: &str, what: &str, env: &dyn Fn(&str) -> Option<String>| {
        env_ref(value, what, env).map_err(|e| {
            match e {
                KmError::Unavailable(m) => KmError::Validation(m),
                e => e,
            }
            .prefixed(path.display())
        })
    };
    let mut cfg: Config = toml::from_str(text).map_err(|e| invalid(&e))?;
    check_names(&cfg).map_err(|e| invalid(&e))?;
    // These paths were TOML strings, so UTF-8: `to_string_lossy` replaces nothing.
    for dir in &mut cfg.profile_dirs {
        *dir = PathBuf::from(env_ref(&dir.to_string_lossy(), "profileDirs", env)?);
    }
    for (name, o) in &mut cfg.objects {
        o.canonicalize();
        // Every object's type, used by a spec or not (review V5); a plan reads it again.
        o.kind().map_err(|e| e.prefixed(format_args!("{}: object '{name}'", path.display())))?;
        check_value_len(o).map_err(|e| invalid(&format_args!("object '{name}': {e}")))?;
    }
    for (name, t) in &mut cfg.tokens {
        // The module resolves when the token is opened ([`TokenCfg::module_path`]): `--module`
        // may replace it, and a run never needs another token's module. Only its form is checked.
        if let Some(m) = &t.module {
            env_ref(m, &format!("token '{name}': module"), &|_| Some(String::new()))?;
        }
        // So are the PIN's and the admin credential's files ([`TokenCfg::pin_path`],
        // [`TokenCfg::so_credential_path`]): a check that opens no token (`validate`, a Nix build
        // sandbox) needs no PIN variable.
        for (what, file) in [("pinFile", &t.pin_file), ("soCredentialFile", &t.so_credential_file)] {
            if let Some(f) = file {
                env_ref(&f.to_string_lossy(), &format!("token '{name}': {what}"), &|_| Some(String::new()))?;
            }
        }
        check_token(t).map_err(|e| invalid(&format_args!("token '{name}': {e}")))?;
    }
    // An object's file resolves when camigrate reads it ([`Config::object_file`]); only its form
    // is checked here, as a module path's.
    for (name, m) in &cfg.object_migrate {
        for (what, value) in [("file", &m.file), ("passphraseFile", &m.passphrase_file)] {
            if let Some(v) = value {
                env_ref(v, &format!("object '{name}': migrate.{what}"), &|_| Some(String::new()))?;
            }
        }
    }
    check_secret_files(&cfg).map_err(|e| invalid(&e))?;
    // A spec's object reference must name something, also when no token ever uses the spec.
    for (spec, s) in &cfg.specs {
        if !cfg.objects.contains_key(&s.object) {
            return Err(invalid(&format_args!("spec '{spec}' references unknown object '{}'", s.object)));
        }
    }
    for s in cfg.specs.values_mut() {
        for v in s.attributes.values_mut().chain(s.public_attributes.values_mut()) {
            if let AttrValue::Mechanisms(m) = v {
                *v = AttrValue::mechanisms(std::mem::take(m));
            }
        }
    }
    for (spec, s) in &mut cfg.specs {
        for (token, on) in &mut s.tokens {
            on.locator.canonicalize().map_err(|e| invalid(&format_args!("spec '{spec}' on token '{token}': {e}")))?;
        }
    }
    check_origins(&cfg).map_err(|e| invalid(&e))?;
    check_transport_keys(&cfg).map_err(|e| invalid(&e))?;
    check_scratch_slots(&cfg).map_err(|e| invalid(&e))?;
    // What loads is usable (review D1): every pair names a token keys.toml defines and plans
    // (`plan_mode`), so no verb meets a spec that loaded and is refused at every use.
    for (spec, s) in &cfg.specs {
        for token in s.tokens.keys() {
            crate::plan::Target::new(&cfg, spec, token).and_then(|t| crate::plan::plan_mode(&t)).map_err(
                |e| match e {
                    KmError::Validation(m) => invalid(&m),
                    other => other,
                },
            )?;
        }
    }
    Ok(cfg)
}

/// A secret key's `valueLen` is one its commitment label can carry, and the one its key type
/// fixes when it fixes one.
fn check_value_len(o: &ObjectCfg) -> std::result::Result<(), String> {
    let Some(len) = o.value_len else { return Ok(()) };
    // The commitment label carries 8 × valueLen bits (docs/DESIGN.md §3.3): bound it so that
    // never overflows (tests/properties.rs: `commitment_labels_are_injective`).
    if len > u64::from(u32::MAX) {
        return Err(format!("valueLen {len} bytes is out of range"));
    }
    if o.class == ObjectClass::SecretKey
        && let Some(kt) = o.key_type
        && let Some(fixed) = kt.fixed_value_len()
        && len != fixed
    {
        return Err(format!("a {kt} key is {fixed} bytes; leave valueLen out or write {fixed}, not {len}"));
    }
    // Lengths no module makes: refused at load rather than by the module at `create` (review D1).
    if o.class == ObjectClass::SecretKey && o.key_type == Some(KeyType::Aes) && ![16, 24, 32].contains(&len) {
        return Err(format!("an AES key is 16, 24 or 32 bytes, not {len}"));
    }
    if o.class == ObjectClass::SecretKey && len == 0 {
        return Err("valueLen 0: a secret key has at least one byte".into());
    }
    Ok(())
}

/// One token's settings agree with each other: `provider` names a family and `moduleProfile` a
/// profile of it, `probe.scratchId` is a hex `CKA_ID`, and an SO credential comes with a user PIN.
fn check_token(t: &TokenCfg) -> std::result::Result<(), String> {
    // `provider` names a family; one profile of it is `moduleProfile`.
    if let Some(p) = t.provider.as_deref().filter(|p| p.contains('/')) {
        return Err(format!(
            "provider = \"{p}\" names one module profile; name its family in provider and the profile in \
             moduleProfile = \"{p}\""
        ));
    }
    if let (Some(family), Some(profile)) = (t.provider.as_deref(), t.module_profile.as_deref())
        && profile.split_once('/').map_or(profile, |(f, _)| f) != family
    {
        return Err(format!("moduleProfile '{profile}' is not of provider '{family}''s family"));
    }
    if let Some(id) = &t.probe.scratch_id
        && crate::hex::decode(id).is_none_or(|b| b.is_empty())
    {
        return Err(format!("probe.scratchId {id:?} is not a hex CKA_ID"));
    }
    // An SO step logs the user out; without a user PIN to return to, the new private key could
    // not be found again, let alone proven.
    if (t.so_credential_file.is_some() || t.so_credential_env.is_some()) && t.pin_file.is_none() && t.pin_env.is_none()
    {
        return Err("soCredentialFile/soCredentialEnv needs a user PIN (pinFile or pinEnv) to return to the user \
                    session"
            .into());
    }
    Ok(())
}

/// A token's `probe.scratchId` is the `CKA_ID` of no locator keys.toml has on that token: the
/// write probes overwrite that slot's key, and a key keys.toml declares there is a real one
/// (review 2026-11-23 D-1: one digit off, the probe replaced it).
fn check_scratch_slots(cfg: &Config) -> std::result::Result<(), String> {
    for (token, t) in &cfg.tokens {
        let Some(scratch) = t.probe.scratch_id.as_deref().and_then(crate::hex::decode) else { continue };
        let mut declared = cfg.specs.iter().filter_map(|(spec, s)| {
            let id = s.tokens.get(token)?.locator.id.as_deref().and_then(crate::hex::decode)?;
            (id == scratch).then_some(spec)
        });
        if let Some(spec) = declared.next() {
            return Err(format!(
                "token '{token}': probe.scratchId {} is the CKA_ID of spec '{spec}''s locator there: the write probes \
                 would overwrite that key; name a slot keys.toml does not use",
                crate::hex::encode(&scratch)
            ));
        }
    }
    Ok(())
}

/// Whether `n` is a name: `[A-Za-z0-9][A-Za-z0-9_-]*` ([`check_names`]; a vendor method's parts,
/// `migrate::Method::from_name`).
pub(crate) fn is_name(n: &str) -> bool {
    n.starts_with(|c: char| c.is_ascii_alphanumeric())
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Object, spec and token names are `[A-Za-z0-9][A-Za-z0-9_-]*`: `check` splits a reference on
/// `.id.`, the lock and `gc` join names with dots, and the Nix library puts them in a shell
/// command. Invalid at load (17), before any other rule names them.
fn check_names(cfg: &Config) -> std::result::Result<(), String> {
    let names = cfg
        .objects
        .keys()
        .map(|n| ("object", n))
        .chain(cfg.specs.keys().map(|n| ("spec", n)))
        .chain(cfg.tokens.keys().map(|n| ("token", n)))
        .chain(cfg.specs.values().flat_map(|s| s.tokens.keys().map(|n| ("token", n))));
    for (what, name) in names {
        if !is_name(name) {
            return Err(format!(
                "{what} name {name:?}: names are letters, digits, '-' and '_', starting with a letter or digit"
            ));
        }
    }
    Ok(())
}

/// Each `transportWith` names a spec realised on its own token whose object is an RSA private
/// key declared to unwrap and never leave the token (docs/CAMIGRATE.md D3).
fn check_transport_keys(cfg: &Config) -> std::result::Result<(), String> {
    for (token, t) in &cfg.tokens {
        let Some(spec) = &t.migrate.transport_with else { continue };
        let what = format!("token '{token}': migrate.transportWith = \"{spec}\"");
        let Some(s) = cfg.specs.get(spec) else { return Err(format!("{what} names no spec")) };
        if !s.tokens.contains_key(token) {
            return Err(format!("{what}, but that spec does not realise it on '{token}'"));
        }
        let rsa = cfg
            .objects
            .get(&s.object)
            .is_some_and(|o| o.class == ObjectClass::PrivateKey && o.key_type == Some(KeyType::Rsa));
        if !rsa {
            return Err(format!("{what}: a transport key is an RSA private key, and '{}' is not", s.object));
        }
        // What it protects is no better guarded than it (camigrate refuses a smaller one found
        // on a token too).
        if let Some(bits) = cfg.objects.get(&s.object).and_then(|o| o.modulus_bits).filter(|b| *b < 2048) {
            return Err(format!("{what}: a transport key has at least 2048 bits, and '{}' declares {bits}", s.object));
        }
        if s.flag("CKA_UNWRAP") != Some(true) || s.flag("CKA_EXTRACTABLE") != Some(false) {
            return Err(format!(
                "{what}: a transport key declares CKA_UNWRAP = true and CKA_EXTRACTABLE = false in its attributes"
            ));
        }
    }
    Ok(())
}

/// No file keys.toml names to hold a secret is in the world-readable Nix store
/// ([`secret_in_store`]): `pinFile`, `soCredentialFile`, `migrate.passphraseFile`, and
/// `migrate.file` when the object's material is secret ([`Config::secret_material`]). A `$NAME`
/// path is checked when it resolves ([`TokenCfg::pin_path`], [`Config::object_file`],
/// [`Config::object_passphrase_file`]), and every secret file again when it is read
/// (`secret::read`), so a link changed since load is caught too.
fn check_secret_files(cfg: &Config) -> std::result::Result<(), String> {
    let literal = |v: &Option<String>| v.clone().filter(|f| !f.starts_with('$')).map(PathBuf::from);
    let tokens = cfg.tokens.iter().flat_map(|(name, t)| {
        [("pinFile", &t.pin_file), ("soCredentialFile", &t.so_credential_file)].into_iter().filter_map(
            move |(what, p)| {
                let p = p.clone().filter(|p| !p.to_string_lossy().starts_with('$'))?;
                Some((format!("token '{name}': {what}"), p))
            },
        )
    });
    let objects = cfg.object_migrate.iter().flat_map(|(object, m)| {
        let file = literal(&m.file).filter(|_| cfg.secret_material(object));
        [("file", file), ("passphraseFile", literal(&m.passphrase_file))]
            .into_iter()
            .filter_map(move |(what, p)| Some((format!("object '{object}': migrate.{what}"), p?)))
    });
    tokens.chain(objects).find_map(|(what, path)| secret_in_store(&what, &path)).map_or(Ok(()), Err)
}

/// Each pair's `origin` fits its object (docs/CONFIG.md): a private or secret key states it; a
/// `publicOnly` adoption, a certificate, a public key and a data object are never created; a
/// `CKA_TRUSTED` key cannot be generated; and an object is created by at most one pair, which
/// says where its material is born and with whose policy, so no order of a run decides either.
/// A file is a birthplace too (docs/FILE.md): `origin = "file"` needs the object's
/// `migrate.file`, and an object born in a file is never also created on a token.
fn check_origins(cfg: &Config) -> std::result::Result<(), String> {
    for (object, m) in &cfg.object_migrate {
        if m.file.is_none() && (m.passphrase_file.is_some() || m.passphrase_env.is_some()) {
            return Err(format!("object '{object}': migrate.passphraseFile/passphraseEnv without migrate.file"));
        }
        if let Some(e) = m.encoding {
            if m.file.is_none() {
                return Err(format!("object '{object}': migrate.encoding without migrate.file"));
            }
            // Any other object's file is taken as it is: a data object's value may well be hex text.
            if cfg.objects.get(object).is_some_and(|o| o.class != ObjectClass::SecretKey) {
                return Err(format!(
                    "object '{object}': migrate.encoding = \"{e}\" applies to secret keys only; any other \
                     object's file is read for what it holds"
                ));
            }
        }
        // A secret key's file may hold its value or hex or base64 text of it, and only the length
        // tells them apart; without one, the file's first read would pin a guess (docs/FILE.md F4).
        if m.file.is_some()
            && m.encoding.is_none()
            && cfg.objects.get(object).is_some_and(|o| o.class == ObjectClass::SecretKey && o.value_len.is_none())
        {
            return Err(format!(
                "object '{object}': a secret key's migrate.file needs the key's valueLen or migrate.encoding = \
                 \"raw\", \"hex\" or \"base64\": its value, hex and base64 of it are told apart by length alone"
            ));
        }
    }
    // Every (spec, token) pair's origin on its own, then across pairs: at most one creates each object.
    let mut created: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (spec_name, spec) in &cfg.specs {
        let Some(object) = cfg.objects.get(&spec.object) else { continue };
        let key = matches!(object.class, ObjectClass::PrivateKey | ObjectClass::SecretKey);
        let has_file = cfg.object_migrate.get(&spec.object).is_some_and(|m| m.file.is_some());
        for (token, on) in &spec.tokens {
            let what = format!("spec '{spec_name}' on token '{token}'");
            let Some(origin) = on.origin else {
                // Unset means "adopt", except for a key's private or secret material, which must say.
                if key && !on.public_only {
                    return Err(format!(
                        "{what}: a private or secret key states its origin: \"create\" (`cakeys create` makes it \
                         here), \"import\" (camigrate brings it), \"file\" (camigrate brings it from the object's \
                         migrate.file) or \"adopt\" (it is already there)"
                    ));
                }
                continue;
            };
            if on.public_only && origin != KeyOrigin::Adopt {
                return Err(format!("{what}: publicOnly adopts the public half, never origin = \"{origin}\""));
            }
            if origin == KeyOrigin::File && !has_file {
                return Err(format!(
                    "{what}: origin = \"file\" reads the object's migrate.file, and object '{}' names none",
                    spec.object
                ));
            }
            if origin != KeyOrigin::Create {
                continue;
            }
            if !key {
                return Err(format!("{what}: {} objects are adopted or imported, never created", object.class));
            }
            if has_file {
                return Err(format!(
                    "{what}: object '{}' is born in its migrate.file, so it is never created on a token; \
                     origin = \"file\", \"import\" or \"adopt\"",
                    spec.object
                ));
            }
            if spec.flag("CKA_TRUSTED") == Some(true) {
                return Err(format!(
                    "{what}: CKA_TRUSTED = true cannot be generated (the token's security officer sets it): \
                     origin = \"adopt\" or \"import\""
                ));
            }
            created.entry(spec.object.as_str()).or_default().push(what);
        }
    }
    if let Some((object, pairs)) = created.iter().find(|(_, pairs)| pairs.len() > 1) {
        return Err(format!(
            "object '{object}' has origin = \"create\" on several pairs ({}): a key is created once, on one \
             token and with one spec's policy; the other pairs import or adopt it",
            pairs.join(", ")
        ));
    }
    Ok(())
}

/// A whole-value environment reference in a path field: `$NAME` or `${NAME}` becomes the value of
/// the environment variable `NAME`, so one shared `keys.toml` can carry a machine-specific pin
/// file or module path. A value with no leading `$` is a literal path. A malformed reference fails
/// at load (exit 17); an unset one fails where the path is used: `module` when its token is
/// opened ([`TokenCfg::module_path`], so `--module` can stand in for it), `pinFile` and
/// `soCredentialFile` when the secret is read ([`TokenCfg::pin_path`]), so a check that touches
/// no token needs no PIN variable.
fn env_ref(value: &str, what: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    let name = match value.strip_prefix('$') {
        Some(rest) => rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(rest),
        None => return Ok(value.to_owned()),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(KmError::Validation(
            format!("{what}: \"{value}\" is neither $NAME, ${{NAME}} nor a literal path").into(),
        ));
    }
    // Unset is this host's environment not providing it, as an unset `pinEnv` is (16); only a
    // reference that is not one is invalid (review 2026-11-23 A-14).
    env(name).ok_or_else(|| {
        KmError::Unavailable(format!("{what}: environment variable {name} (\"{value}\") is not set").into())
    })
}

impl Config {
    /// The file `object`'s material is born in (`[objects.<o>.migrate] file`, docs/FILE.md), its
    /// `$NAME` reference resolved by `env` now; `None` when the object names none. Resolved at
    /// use, as a module path is, so hosts that only check load keys.toml without the variable.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) for an unset `$NAME`; `Validation` (17) for a secret file that resolves into
    /// `/nix/store` ([`Self::secret_material`], `secret_in_store`): the store is world-readable.
    pub fn object_file(&self, object: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        let Some(file) = self.object_migrate.get(object).and_then(|m| m.file.as_deref()) else { return Ok(None) };
        let what = format!("object '{object}': migrate.file");
        let path = PathBuf::from(env_ref(file, &what, env)?);
        if self.secret_material(object)
            && let Some(why) = secret_in_store(&what, &path)
        {
            return Err(KmError::Validation(why.into()));
        }
        Ok(Some(path))
    }

    /// The file holding the passphrase of `object`'s encrypted key file (`migrate.passphraseFile`),
    /// `$NAME` resolved by `env`; `None` when it names none.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) for an unset `$NAME`; `Validation` (17) for a path that resolves into
    /// `/nix/store`: a passphrase is a secret whatever it decrypts.
    pub fn object_passphrase_file(
        &self,
        object: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<PathBuf>> {
        let Some(file) = self.object_migrate.get(object).and_then(|m| m.passphrase_file.as_deref()) else {
            return Ok(None);
        };
        let what = format!("object '{object}': migrate.passphraseFile");
        let path = PathBuf::from(env_ref(file, &what, env)?);
        if let Some(why) = secret_in_store(&what, &path) {
            return Err(KmError::Validation(why.into()));
        }
        Ok(Some(path))
    }

    /// Whether `object`'s material is secret at rest: a private or secret key, or a data object a
    /// spec declares `CKA_PRIVATE = true`.
    #[must_use]
    pub fn secret_material(&self, object: &str) -> bool {
        match self.objects.get(object).map(|o| o.class) {
            Some(ObjectClass::PrivateKey | ObjectClass::SecretKey) => true,
            Some(ObjectClass::Data) => {
                self.specs.values().any(|s| s.object == object && s.flag("CKA_PRIVATE") == Some(true))
            }
            _ => false,
        }
    }

    /// The (spec, token) pairs a verb's address selects (`[<object>] [--spec] [--token]`,
    /// docs/CAKEYS.md): each part left out selects every one; an empty result is no error.
    ///
    /// # Errors
    ///
    /// `Validation` (17) when a part names nothing keys.toml has, or `--spec` realises
    /// another object than the one named.
    pub fn select(&self, object: Option<&str>, spec: Option<&str>, token: Option<&str>) -> Result<Vec<(&str, &str)>> {
        if let Some(o) = object
            && !self.objects.contains_key(o)
        {
            return Err(KmError::Validation(format!("unknown object '{o}'").into()));
        }
        if let Some(s) = spec {
            let Some(cfg) = self.specs.get(s) else {
                return Err(KmError::Validation(format!("unknown spec '{s}'").into()));
            };
            if let Some(o) = object.filter(|o| *o != cfg.object) {
                return Err(KmError::Validation(format!("spec '{s}' realises '{}', not '{o}'", cfg.object).into()));
            }
        }
        if let Some(t) = token
            && !self.tokens.contains_key(t)
        {
            return Err(KmError::Validation(format!("unknown token '{t}'").into()));
        }
        Ok(self
            .specs
            .iter()
            .filter(|(n, s)| spec.is_none_or(|w| w == n.as_str()) && object.is_none_or(|o| o == s.object))
            .flat_map(|(n, s)| s.tokens.keys().map(move |t| (n.as_str(), t.as_str())))
            .filter(|(_, t)| token.is_none_or(|w| w == *t))
            .collect())
    }

    /// The one (spec, token) pair a verb's address names: an object or `--spec`, narrowed by
    /// the others when the object is realised more than once.
    ///
    /// # Errors
    ///
    /// `Validation` (17) when neither an object nor `--spec` is given, or as [`Self::select`],
    /// or when no pair matches; `Ambiguous` (12) when several do and `--spec`/`--token` has to
    /// narrow it.
    pub fn address(&self, object: Option<&str>, spec: Option<&str>, token: Option<&str>) -> Result<(String, String)> {
        if object.is_none() && spec.is_none() {
            return Err(KmError::Validation("name an object, or a spec with --spec".into()));
        }
        let pairs = self.select(object, spec, token)?;
        let what = object.map_or_else(|| format!("spec '{}'", spec.unwrap_or_default()), |o| format!("object '{o}'"));
        match pairs.as_slice() {
            [(s, t)] => Ok(((*s).to_owned(), (*t).to_owned())),
            [] => Err(KmError::Validation(
                format!(
                    "no spec places {what}{}{}",
                    spec.filter(|_| object.is_some()).map_or_else(String::new, |s| format!(" through spec '{s}'")),
                    token.map_or_else(String::new, |t| format!(" on token '{t}'"))
                )
                .into(),
            )),
            _ => Err(KmError::Ambiguous(
                format!("{what} has several (spec, token) pairs {pairs:?}; pass --spec/--token").into(),
            )),
        }
    }
}

/// Module that realised an object (`C_GetInfo` plus the loaded file). Provenance only: on verify a
/// different build identity is a warning, and so is a different `hash` at the same `path` (the
/// file replaced in place: the case a path outside the Nix store cannot show); a different
/// `path` alone (a Nix rebuild) is a note. Identity itself is enforced by the CA-IDs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    /// The file the dynamic loader mapped, symlinks resolved — whatever named it in keys.toml or
    /// with `--module` (a bare name, a profile symlink, `$NAME`).
    pub path: String,
    /// SRI SHA-256 of that file; absent when it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// `CK_INFO.libraryDescription`.
    pub description: String,
    /// `CK_INFO.manufacturerID`.
    pub manufacturer: String,
    /// `CK_INFO.libraryVersion`.
    pub version: String,
    /// `CK_INFO.cryptokiVersion`: the PKCS#11 version the module implements.
    pub cryptoki: String,
}

impl ModuleInfo {
    /// Equal apart from the file (`path`, `hash`).
    #[must_use]
    pub fn same_build_identity(&self, other: &Self) -> bool {
        (&self.description, &self.manufacturer, &self.version, &self.cryptoki)
            == (&other.description, &other.manufacturer, &other.version, &other.cryptoki)
    }
}

/// The token a realisation was made on (`C_GetTokenInfo`): provenance, like [`ModuleInfo`]; another
/// token is a warning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInfo {
    /// `CK_TOKEN_INFO.model`.
    pub model: String,
    /// `CK_TOKEN_INFO.serialNumber`.
    pub serial: String,
    /// `CK_TOKEN_INFO.firmwareVersion`.
    pub firmware: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic Nix-library fixture must stay a valid lock of the current schema.
    #[test]
    fn fixture_lock_parses() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"));
        let lock = load_lock(path).unwrap();
        assert_eq!(lock.realisations["signing-soft"]["softhsm"].binding, Some(Binding::PopSign));
        // A recorded CKA_ID loads in lower case, as keys.toml's does: `0A` and `0a` are one
        // locator, never a change to review (review D1). A non-hex one is no lock cakeys wrote.
        let text = std::fs::read_to_string(path).unwrap();
        let with_id = |id: &str| {
            text.replace(
                "locator = { CKA_LABEL = \"signing\" }",
                &format!("locator = {{ CKA_LABEL = \"signing\", CKA_ID = \"{id}\" }}"),
            )
        };
        let lock = parse_lock(&with_id("0A"), path).unwrap();
        assert_eq!(lock.realisations["signing-soft"]["softhsm"].locator.id.as_deref(), Some("0a"));
        let e = parse_lock(&with_id("zz"), path).unwrap_err();
        assert!(e.to_string().contains("CKA_ID 'zz' is not hex"), "{e}");
    }

    /// Observation keys of a newer cakeys load and survive a rewrite (the TUF re-serialization
    /// rule); anywhere else an unknown key is still a refused lock, `provenance` included.
    #[test]
    fn unknown_observation_keys_are_kept_on_rewrite() {
        let fixture = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"));
        let text = std::fs::read_to_string(fixture).unwrap();
        let known = "provider = \"softhsm\"\ncakeysVersion = \"0.1.0\"\n";
        assert!(text.contains(known));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        std::fs::write(&path, text.replacen(known, &format!("{known}builder = \"ci-7\"\nrun = {{ id = 3 }}\n"), 1))
            .unwrap();
        let lock = load_lock(&path).unwrap();
        let extra = |l: &Lock| {
            let key = l.realisations["signing-soft"]["softhsm"].observation.clone().unwrap();
            l.observations[&key].extra.clone()
        };
        assert_eq!(extra(&lock).keys().collect::<Vec<_>>(), ["builder", "run"]);
        save_lock(&path, &lock).unwrap();
        assert_eq!(extra(&load_lock(&path).unwrap()), extra(&lock));
        // The rename left nothing behind but the lock.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // A compared table takes no unknown key, and neither does the object's history.
        for (table, key) in [
            ("[realisations.signing-soft.softhsm]\n", "builder = \"ci-7\"\n"),
            ("[realisations.signing-soft.softhsm]\n", "provenance = { builder = \"ci-7\" }\n"),
        ] {
            std::fs::write(&path, text.replacen(table, &format!("{table}{key}"), 1)).unwrap();
            assert!(matches!(load_lock(&path), Err(KmError::Validation(_))), "{key}");
        }
    }

    /// A realisation names an observation the lock has (17 otherwise); an origin names a known
    /// method; `gc` reports and drops exactly the observations no remaining realisation names.
    #[test]
    fn observations_are_referenced_and_collected() {
        let path = Path::new("test.lock");
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let set = |lock: &mut Lock, f: &dyn Fn(&mut LockRealisation)| {
            f(lock.realisations.get_mut("s").unwrap().get_mut("t").unwrap());
        };
        let mut lock = attestable_lock();
        set(&mut lock, &|r| r.observation = Some(sri.into()));
        let err = lock.clone().validate(path).unwrap_err();
        assert!(err.to_string().contains("is not in the lock"), "{err}");
        lock.observations.insert(sri.into(), Observation::default());
        lock.observations.insert("sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=".into(), Observation::default());
        lock.clone().validate(path).unwrap();
        // Every observation's module hash is checked, not only the first one's (review
        // config.rs F2): a good one first, a malformed one after.
        let module = |hash: &str| ModuleInfo {
            path: "/m.so".into(),
            hash: Some(hash.into()),
            description: String::new(),
            manufacturer: String::new(),
            version: String::new(),
            cryptoki: String::new(),
        };
        let mut hashed = lock.clone();
        let mut entries = hashed.observations.values_mut();
        entries.next().unwrap().module = Some(module(sri));
        entries.next().unwrap().module = Some(module("sha256-x"));
        let err = hashed.validate(path).unwrap_err();
        assert!(err.to_string().contains("module hash \"sha256-x\""), "{err}");
        assert!(matches!(lock.token_observation("t"), TokenObservation::One(_)));
        assert!(matches!(lock.token_observation("other"), TokenObservation::None));

        let mut bad = lock.clone();
        let origin = Origin {
            from: "a".into(),
            method: "carrier-pigeon".into(),
            exposure: crate::migrate::Exposure::Public,
            declared: false,
        };
        set(&mut bad, &|r| r.provenance = Some(Provenance { origin: Some(origin.clone()) }));
        assert!(bad.validate(path).unwrap_err().to_string().contains("origin method"));

        let cfg: Config = toml::from_str(
            "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\ntokens.t = { locator = { CKA_LABEL = \"k\" } }\n",
        )
        .unwrap();
        let unnamed = "observations.\"sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=\"";
        assert_eq!(gc(&cfg, &mut lock.clone(), false), [unnamed]);
        // With the spec gone, the realisation goes, and so does the observation only it named.
        let cfg = Config { specs: BTreeMap::new(), ..cfg };
        let stale = gc(&cfg, &mut lock, true);
        assert_eq!(stale.len(), 3, "{stale:?}");
        assert!(lock.realisations.is_empty() && lock.observations.is_empty());
    }

    /// `gc` leaves a lock that loads: an object renamed in keys.toml before `lock` ran
    /// takes the realisation that still names it along (it once stayed, naming an object `gc`
    /// had dropped, and every later run refused the lock, `lock` and `gc` included). And no
    /// lock that would not load is ever written: `save_lock` refuses it and keeps the old one.
    #[test]
    fn gc_and_save_leave_a_lock_that_loads() {
        let path = Path::new("test.lock");
        let mut lock = attestable_lock();
        let renamed: Config = toml::from_str(
            "[objects.renamed]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"renamed\"\ntokens.t = { locator = { CKA_LABEL = \"k\" } }\n",
        )
        .unwrap();
        let stale = gc(&renamed, &mut lock, true);
        assert!(stale.contains(&"realisations.s.t".to_owned()) && stale.contains(&"objects.k".to_owned()), "{stale:?}");
        lock.clone().validate(path).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keys.lock");
        let mut broken = attestable_lock();
        broken.objects.clear();
        // Saved after a token write, a lock that would not load is a lock not written (21), with
        // the load rule it breaks (review 2026-11-23 A-17).
        let e = save_lock(&file, &broken).unwrap_err();
        assert!(e.exit_code() == 21 && e.to_string().contains("is not in the lock"), "{e}");
        assert!(!file.exists(), "an invalid lock was written");
        save_lock(&file, &attestable_lock()).unwrap();
        load_lock(&file).unwrap();
    }

    /// A lock that cannot be saved is `LockUnwritable` (21), whatever stage of the write failed:
    /// a run that changed the token must say its record is missing, not exit 1 like any I/O.
    #[test]
    fn a_lock_that_cannot_be_saved_is_its_own_code() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root writes anyway (access(2) and the write both succeed).
        if std::fs::File::create(ro.join("probe")).is_ok() {
            return;
        }
        let e = save_lock(&ro.join("keys.lock"), &attestable_lock()).unwrap_err();
        assert_eq!(e.exit_code(), 21, "{e}");
        assert!(e.to_string().contains("lock cannot be written"), "{e}");
    }

    /// A symlinked lock (a NixOS layout: the lock in a checked-out repository) is written through
    /// to its target, never replaced by a copy the repository never sees (config.rs F7).
    #[test]
    fn a_symlinked_lock_is_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let (real, link) = (dir.path().join("repo.lock"), dir.path().join("keys.lock"));
        save_lock(&real, &Lock { version: LOCK_VERSION, ..Default::default() }).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        save_lock(&link, &attestable_lock()).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link was replaced");
        let text = |p: &Path| std::fs::read_to_string(p).unwrap();
        assert_eq!(text(&real), toml::to_string_pretty(&attestable_lock()).unwrap(), "the target was not written");
        assert_eq!(unwritable(&link, false), None);
    }

    /// Object, spec and token names have one grammar, checked at load (17): a reference splits
    /// on `.id.`, and shell commands are built from them.
    #[test]
    fn names_are_letters_digits_dashes_and_underscores() {
        let load = |object: &str, spec: &str, token: &str| {
            let text = format!(
                "[tokens.\"{token}\"]\ntokenLabel = \"t\"\n\n\
                 [objects.\"{object}\"]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                 [specs.\"{spec}\"]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
                 tokens.\"{token}\" = {{ locator = {{ CKA_LABEL = \"k\" }}, origin = \"adopt\" }}\n"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        load("k", "k-soft_2", "0soft").unwrap();
        for (object, spec, token, what) in [
            ("a b; echo pwned #", "s", "t", "object name \"a b; echo pwned #\""),
            ("k.id.x", "s", "t", "object name \"k.id.x\""),
            ("k", "-s", "t", "spec name \"-s\""),
            ("k", "s", "my token", "token name \"my token\""),
            ("k", "s", "", "token name \"\""),
            ("k", "s", "tök", "token name \"tök\""),
        ] {
            let e = load(object, spec, token).unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        }
    }

    /// Every pair says how its object comes to be there (`origin`), checked at load (17): a
    /// private or secret key states it; what is never generated (a certificate, a public key, a
    /// data object, a `publicOnly` adoption, a `CKA_TRUSTED` key) is not `create`; and an object
    /// is created by one pair at most. The retired `autoCreate` and `createOn` are unknown fields.
    #[test]
    fn origins_say_how_an_object_comes_to_be_on_a_token() {
        let load = |class: &str, a: &str, b: &str, second_spec: &str| {
            // A usage each pair can prove possession by; none for what has no private half.
            let attributes = if class.contains("CKO_CERTIFICATE") || a.contains("publicOnly") {
                ""
            } else {
                "attributes = { CKA_SIGN = true }\n"
            };
            let text = format!(
                "[tokens.a]\ntokenLabel = \"a\"\n[tokens.b]\ntokenLabel = \"b\"\n\n\
                 [objects.k]\n{class}\n\n\
                 [specs.k]\nobject = \"k\"\n{attributes}\
                 tokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{a} }}\n\
                 tokens.b = {{ locator = {{ CKA_LABEL = \"k\" }}{b} }}\n{second_spec}"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
        let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
        let cert = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
        let (create, import, adopt) = (", origin = \"create\"", ", origin = \"import\"", ", origin = \"adopt\"");
        let cfg = load(ec, create, import, "").unwrap();
        let on = |t: &str| cfg.specs["k"].tokens[t].key_origin();
        assert_eq!((on("a"), on("b")), (KeyOrigin::Create, KeyOrigin::Import));
        load(aes, adopt, adopt, "").unwrap();
        // What is never created is adopted unless it says otherwise.
        let cfg = load(cert, "", import, "").unwrap();
        assert_eq!(cfg.specs["k"].tokens["a"].key_origin(), KeyOrigin::Adopt);
        load(ec, ", publicOnly = true", ", publicOnly = true, origin = \"adopt\"", "").unwrap();

        let refused = |r: Result<Config>, what: &str| {
            let e = r.unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        };
        refused(load(ec, "", adopt, ""), "spec 'k' on token 'a': a private or secret key states its origin");
        refused(load(aes, adopt, "", ""), "spec 'k' on token 'b': a private or secret key states its origin");
        refused(load(cert, create, "", ""), "CKO_CERTIFICATE objects are adopted or imported, never created");
        refused(load(ec, ", publicOnly = true, origin = \"import\"", adopt, ""), "never origin = \"import\"");
        let trusted = "\n[specs.t]\nobject = \"k\"\nattributes = { CKA_WRAP = true, CKA_TRUSTED = true }\n";
        refused(
            load(aes, adopt, adopt, &format!("{trusted}tokens.a = {{ locator = {{ CKA_LABEL = \"t\" }}{create} }}\n")),
            "CKA_TRUSTED = true cannot be generated",
        );
        // Created once: two tokens, or two specs on one token, would leave it to the run.
        refused(load(ec, create, create, ""), "has origin = \"create\" on several pairs");
        let second =
            format!("\n[specs.k2]\nobject = \"k\"\ntokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{create} }}\n");
        refused(load(ec, create, adopt, &second), "spec 'k' on token 'a', spec 'k2' on token 'a'");
        // The retired keys.
        refused(load(ec, ", autoCreate = true", adopt, ""), "unknown field `autoCreate`");
        refused(load(&format!("{ec}\ncreateOn = \"a\""), create, adopt, ""), "unknown field `createOn`");
    }

    /// An object born in a file (docs/FILE.md F1, F2): `origin = "file"` on any number of pairs,
    /// read from the object's `migrate.file`, which is never part of the type the lock pins; a
    /// file is a birthplace, so the object is never also created; a secret file is kept out of
    /// the Nix store, a literal path at load and a `$NAME` one when it is read.
    #[test]
    fn objects_born_in_files_read_their_migrate_file() {
        let load = |object: &str, a: &str, b: &str| {
            // A usage each pair can prove possession or commit by (DES3 only by encrypting).
            let attributes = match object {
                o if o.contains("CKO_CERTIFICATE") => "",
                o if o.contains("CKK_DES3") => "attributes = { CKA_ENCRYPT = true }\n",
                _ => "attributes = { CKA_SIGN = true }\n",
            };
            let text = format!(
                "[tokens.a]\ntokenLabel = \"a\"\n[tokens.b]\ntokenLabel = \"b\"\n\n\
                 [objects.k]\n{object}\n\n\
                 [specs.k]\nobject = \"k\"\n{attributes}\
                 tokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{a} }}\n\
                 tokens.b = {{ locator = {{ CKA_LABEL = \"k\" }}{b} }}\n"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
        let cert = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
        let file = |path: &str| format!("\nmigrate = {{ file = \"{path}\" }}");
        let (from_file, create, adopt) = (", origin = \"file\"", ", origin = \"create\"", ", origin = \"adopt\"");
        let cfg = load(&(ec.to_owned() + &file("/run/keys/k.pem")), from_file, from_file).unwrap();
        assert_eq!(cfg.specs["k"].tokens["b"].key_origin(), KeyOrigin::File);
        assert_eq!(
            cfg.objects["k"],
            ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Ec)) }
        );
        assert_eq!(cfg.object_file("k", &|_| None).unwrap(), Some(PathBuf::from("/run/keys/k.pem")));
        // A `$NAME` path resolves when it is read: unset, it fails that read, not the load.
        let cfg = load(&(ec.to_owned() + &file("$KEY_FILE")), from_file, adopt).unwrap();
        assert!(cfg.object_file("k", &|_| None).is_err());
        let store = |_: &str| Some("/nix/store/abc-k.pem".to_owned());
        assert!(cfg.object_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        // A certificate is no secret: from the store it may come.
        let cfg = load(&(cert.to_owned() + &file("/nix/store/abc-c.pem")), from_file, "").unwrap();
        assert!(cfg.object_file("k", &|_| None).unwrap().is_some());

        let refused = |r: Result<Config>, what: &str| {
            let e = r.unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        };
        refused(
            load(ec, from_file, adopt),
            "origin = \"file\" reads the object's migrate.file, and object 'k' names none",
        );
        refused(load(&(ec.to_owned() + &file("/k.pem")), create, adopt), "is born in its migrate.file");
        refused(load(&(ec.to_owned() + &file("/nix/store/abc-k.pem")), from_file, adopt), "Nix store");
        refused(
            load(&(ec.to_owned() + "\nmigrate = { passphraseFile = \"/p\" }"), adopt, adopt),
            "without migrate.file",
        );
        refused(load(&(ec.to_owned() + &file("$")), adopt, adopt), "migrate.file");
        // A secret key's file may say how it spells the value; no other object's may.
        let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"";
        let encoded = |e: &str| format!("\nmigrate = {{ file = \"/k\", encoding = \"{e}\" }}");
        for e in ["raw", "hex", "base64"] {
            let cfg = load(&(aes.to_owned() + &encoded(e)), from_file, adopt).unwrap();
            assert_eq!(cfg.object_migrate["k"].encoding.map(|e| e.to_string()).as_deref(), Some(e));
        }
        // Without valueLen, the encoding is said; a key type's fixed length is a valueLen.
        refused(
            load(&(aes.to_owned() + &file("/k")), from_file, adopt),
            "needs the key's valueLen or migrate.encoding",
        );
        load(&(aes.to_owned() + "\nvalueLen = 16" + &file("/k")), from_file, adopt).unwrap();
        load(&("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"".to_owned() + &file("/k")), from_file, adopt)
            .unwrap();
        refused(load(&(ec.to_owned() + &encoded("hex")), from_file, adopt), "applies to secret keys only");
        refused(load(&(aes.to_owned() + &encoded("base32")), from_file, adopt), "unknown variant `base32`");
        refused(
            load(&(aes.to_owned() + "\nmigrate = { encoding = \"hex\" }"), adopt, adopt),
            "migrate.encoding without migrate.file",
        );
        refused(load(&(ec.to_owned() + "\nmigrate = { path = \"/k\" }"), adopt, adopt), "unknown field `path`");
        refused(
            load(&(ec.to_owned() + &file("/k.pem")), ", publicOnly = true, origin = \"file\"", adopt),
            "never origin = \"file\"",
        );
    }

    /// Every file keys.toml names to hold a secret is refused (17) when it resolves into the
    /// world-readable Nix store: `pinFile`, `soCredentialFile`, `migrate.passphraseFile`, and a
    /// secret object's `migrate.file`; at load for a literal path (or a `$NAME` pin file, which
    /// load resolves), when camigrate resolves a `$NAME` migrate path; through a symlink or a
    /// `..` as directly (review config.rs F4).
    #[test]
    fn no_secret_file_is_in_the_nix_store() {
        let dir = tempfile::tempdir().unwrap();
        let result = dir.path().join("result");
        std::os::unix::fs::symlink("/nix/store", &result).unwrap();
        let elsewhere = dir.path().join("keys");
        std::fs::create_dir(&elsewhere).unwrap();
        let in_store = [
            "/nix/store/abc-secret".to_owned(),
            format!("{}/abc-secret", result.display()),
            format!("{}/../result/abc-secret", elsewhere.display()),
        ];
        let outside = [format!("{}/secret", elsewhere.display()), format!("{}/../keys/secret", result.display())];
        let ec = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n";
        let fields = [
            ("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"{}\"\n", "token 't': pinFile"),
            ("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"/p\"\nsoCredentialFile = \"{}\"\n", "soCredentialFile"),
            ("{ec}migrate = { file = \"/run/k.p12\", passphraseFile = \"{}\" }\n", "migrate.passphraseFile"),
            ("{ec}migrate = { file = \"{}\" }\n", "object 'k': migrate.file"),
        ];
        let load = |text: &str| parse_config_with(text, Path::new("keys.toml"), &|_| None);
        for (template, what) in fields {
            let at = |p: &str| template.replace("{ec}", ec).replace("{}", p);
            for p in &in_store {
                let e = load(&at(p)).unwrap_err();
                assert!(
                    matches!(&e, KmError::Validation(m) if m.contains(what) && m.contains("Nix store")),
                    "{what} {p}: {e}"
                );
            }
            for p in &outside {
                load(&at(p)).unwrap_or_else(|e| panic!("{what} {p}: {e}"));
            }
        }
        // A `$NAME` pin file is checked when it resolves, as a migrate path is.
        let cfg = load("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"$PIN_FILE\"\n").unwrap();
        let pin = cfg.tokens["t"].pin_path("t", &|_| Some(in_store[1].clone()));
        assert!(matches!(&pin, Err(KmError::Validation(m)) if m.contains("Nix store")), "{:?}", pin.err());
        let fine = cfg.tokens["t"].pin_path("t", &|_| Some(outside[0].clone()));
        assert_eq!(fine.unwrap(), Some(PathBuf::from(&outside[0])));
        // A `$NAME` migrate path is checked when camigrate resolves it, the passphrase's whatever
        // the object holds.
        let cfg = load(&format!("{ec}migrate = {{ file = \"$KEY\", passphraseFile = \"$PASS\" }}\n")).unwrap();
        let store = |_: &str| Some(in_store[2].clone());
        assert!(cfg.object_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        assert!(cfg.object_passphrase_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        let fine = |_: &str| Some(outside[0].clone());
        assert_eq!(cfg.object_passphrase_file("k", &fine).unwrap(), Some(PathBuf::from(&outside[0])));
        let cert = "[objects.k]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n";
        let cfg = load(&format!("{cert}migrate = {{ file = \"$KEY\", passphraseFile = \"$PASS\" }}\n")).unwrap();
        assert!(cfg.object_file("k", &store).unwrap().is_some(), "a certificate is no secret");
        assert!(cfg.object_passphrase_file("k", &store).is_err(), "a passphrase is");
    }

    /// The store guard compares resolved paths component by component: a link into the root, a
    /// `..` out of it and a sibling whose name only starts like it are told apart, existing or not.
    #[test]
    fn paths_resolve_before_they_compare() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(dir.path().join("store-not")).unwrap();
        std::os::unix::fs::symlink(&root, dir.path().join("link")).unwrap();
        let under = |p: &str| resolves_under(&dir.path().join(p), &root);
        assert!(under("store/a"));
        assert!(under("link/a/b"), "through a link, to a file that does not exist");
        assert!(under("store-not/../store/a"));
        assert!(!under("store-not/a"), "a string prefix is no parent");
        assert!(!under("store/../a"));
        assert!(!under("link/../a"), "the link's target's parent, not the link's");
        assert!(!under("elsewhere/a"));
    }

    /// `$NAME`/`${NAME}` in `pinFile` and `module` read the path from the environment when it is
    /// used; a malformed reference is invalid at load (17), an unset one where the path is
    /// resolved (17), and a spec must reference an existing object at load.
    #[test]
    fn env_references_and_object_refs_are_checked_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let load = |body: &str| {
            let p = dir.join("keys.toml");
            std::fs::write(&p, body).unwrap();
            load_config_with(&p, &|name| match name {
                "KM_UNIT_TEST_PIN" => Some("/env/pin".to_owned()),
                "KM_UNIT_TEST_MGM" => Some("/env/mgm".to_owned()),
                _ => None,
            })
        };
        let head = "[tokens.t]\ntokenLabel = \"x\"\n";
        let env = |name: &str| (name == "KM_UNIT_TEST_PIN").then(|| "/env/pin".to_owned());
        // A literal path is as written; $NAME and ${NAME} expand when the path is resolved.
        let cfg = load(&format!("{head}pinFile = \"/literal/pin\"\n")).unwrap();
        assert_eq!(cfg.tokens["t"].pin_path("t", &env).unwrap(), Some(PathBuf::from("/literal/pin")));
        let cfg =
            load(&format!("{head}pinFile = \"$KM_UNIT_TEST_PIN\"\nmodule = \"${{KM_UNIT_TEST_PIN}}\"\n")).unwrap();
        assert_eq!(cfg.tokens["t"].pin_path("t", &env).unwrap(), Some(PathBuf::from("/env/pin")));
        assert_eq!(
            cfg.tokens["t"].module_path("t", &|_| Some("/env/pin".to_owned())).unwrap().as_deref(),
            Some("/env/pin")
        );
        // A malformed reference fails at load, naming the file first, as every other load error
        // does (review config.rs F6).
        let file = format!("invalid: {}: ", dir.join("keys.toml").display());
        let err = load(&format!("{head}pinFile = \"$HOME/x\"\n")).unwrap_err().to_string();
        assert!(err.starts_with(&file) && err.contains("neither $NAME"), "{err}");
        for body in [
            "profileDirs = [\"$KM_UNIT_TEST_UNSET\"]\n".to_owned(),
            format!("{head}soCredentialFile = \"$\"\n"),
            format!("{head}module = \"$HOME/x.so\"\n"),
            "[objects.o]\nclass = \"CKO_DATA\"\nmigrate = { file = \"${HOME\" }\n".to_owned(),
        ] {
            let err = load(&body).unwrap_err().to_string();
            assert!(err.starts_with(&file), "{body}: {err}");
        }
        // A module, a PIN file and a credential file resolve when used, not at load: an unset
        // variable fails only a run that opens that token (without --module for the module), so
        // `validate` and a Nix build sandbox, which set none, load the file; a malformed
        // reference still fails at load. Unset at use is the environment's, not the file's: 16
        // (review 2026-11-23 A-14).
        let unset = load(&format!(
            "{head}module = \"$KM_UNIT_TEST_UNSET\"\npinFile = \"$KM_UNIT_TEST_UNSET\"\n\
             soCredentialFile = \"$KM_UNIT_TEST_UNSET\"\n"
        ))
        .unwrap();
        let t = &unset.tokens["t"];
        for err in [
            t.module_path("t", &|_| None).unwrap_err(),
            t.pin_path("t", &|_| None).unwrap_err(),
            t.so_credential_path("t", &|_| None).unwrap_err(),
        ] {
            assert!(matches!(err, KmError::Unavailable(_)), "{err}");
            assert!(err.to_string().contains("KM_UNIT_TEST_UNSET"), "{err}");
        }
        assert!(load(&format!("{head}module = \"$HOME/x.so\"\n")).is_err());
        // soCredentialFile expands the same way; an admin credential only comes with a user PIN.
        let cfg = load(&format!("{head}pinFile = \"/p\"\nsoCredentialFile = \"$KM_UNIT_TEST_MGM\"\n")).unwrap();
        let mgm = |name: &str| (name == "KM_UNIT_TEST_MGM").then(|| "/env/mgm".to_owned());
        assert_eq!(cfg.tokens["t"].so_credential_path("t", &mgm).unwrap(), Some(PathBuf::from("/env/mgm")));
        for admin in ["soCredentialFile = \"/so\"", "soCredentialEnv = \"SO\""] {
            let err = load(&format!("{head}{admin}\n")).unwrap_err();
            assert!(err.to_string().contains("needs a user PIN"), "{err}");
        }
        // A spec's object reference must exist, also when nothing uses the spec.
        let err = load(&format!(
            "{head}\n[objects.o]\nclass = \"CKO_DATA\"\n\n[specs.s]\nobject = \"missing\"\ntokens = {{}}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown object 'missing'"), "{err}");
    }

    /// A class or key type cakeys does not manage is invalid when keys.toml loads (17), not when
    /// a token is first asked for it.
    #[test]
    fn unknown_classes_and_key_types_are_invalid_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("keys.toml");
        for object in ["class = \"CKO_OTP_KEY\"", "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES2\""] {
            std::fs::write(&p, format!("[objects.o]\n{object}\n")).unwrap();
            let err = load_config(&p).unwrap_err();
            assert!(matches!(err, KmError::Validation(_)), "{err}");
        }
    }

    /// A DES3 key is 24 bytes: `valueLen` left out loads as 24 (the same type, spec digest and
    /// commitment label as writing it), and any other length is invalid at load (17).
    #[test]
    fn des3_value_len_is_the_key_types() {
        let des3 = |len: &str| {
            let text = format!("[objects.o]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"\n{len}\n");
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        assert_eq!(des3("").unwrap().objects["o"].value_len, Some(24));
        assert_eq!(des3("").unwrap().objects["o"], des3("valueLen = 24").unwrap().objects["o"]);
        for wrong in ["valueLen = 16", "valueLen = 0", "valueLen = 32"] {
            let err = des3(wrong).unwrap_err();
            assert!(matches!(&err, KmError::Validation(m) if m.contains("a CKK_DES3 key is 24 bytes")), "{err}");
        }
        // Only a secret key takes the fixed length; another class is refused by its type at load.
        let text = "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_DES3\"\n";
        let err = parse_config_with(text, Path::new("keys.toml"), &|_| None).unwrap_err();
        assert!(matches!(&err, KmError::Unsupported(m) if m.contains("CKO_PRIVATE_KEY/CKK_DES3")), "{err}");
    }

    /// Downgrade detection compares ranks: an inverted order would silently disable it. The
    /// `pop-*` methods share rank 0: each proves possession of the same key.
    #[test]
    fn binding_ranks_are_pinned() {
        assert!(Binding::PopSign.rank() < Binding::TokenAsserted.rank());
        assert_eq!(Binding::PopSign.to_string(), "pop-sign");
        assert_eq!(Binding::PopSignPin.to_string(), "pop-sign-pin");
        assert_eq!(Binding::PopEcdh.to_string(), "pop-ecdh");
        assert_eq!(Binding::PopDecrypt.to_string(), "pop-decrypt");
        assert_eq!(Binding::PopUnwrap.to_string(), "pop-unwrap");
        assert_eq!(Binding::PopSignPin.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::PopEcdh.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::PopDecrypt.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::PopUnwrap.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::TokenAsserted.to_string(), "token-asserted");
    }

    /// A minimal valid lock with one object and realisation, for the attestation-invariant
    /// tests: the caller mutates it and expects `validate` to accept or refuse.
    fn attestable_lock() -> Lock {
        let mut ids = BTreeMap::new();
        ids.insert("rfc7093m4".to_owned(), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_owned());
        let mut lock = Lock { version: LOCK_VERSION, ..Default::default() };
        lock.objects.insert(
            "k".into(),
            LockObject {
                object_type: Some(ObjectCfg {
                    curve: Some("secp256r1".into()),
                    ..ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Ec))
                }),
                ids,
                ..Default::default()
            },
        );
        lock.realisations.insert(
            "s".into(),
            [(
                "t".into(),
                LockRealisation {
                    object: "k".into(),
                    locator: Locator { label: Some("k".into()), id: None },
                    spec_digest: "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
                    mode: Mode::Direct,
                    schemes: ["rfc7093m4".to_owned()].into_iter().collect(),
                    public_only: false,
                    binding: Some(Binding::PopSign),
                    attestation: None,
                    policy: BTreeMap::new(),
                    immutables: Immutables::default(),
                    observation: None,
                    observed: None,
                    provenance: None,
                },
            )]
            .into_iter()
            .collect(),
        );
        lock
    }

    /// Attestation IDs are per device and never stand alone (§3.7): they live on the realisation
    /// that computed them — never in the object's shared `ids`, where the same material attested
    /// on a second TPM would collide — and that realisation must also hold a portable scheme.
    #[test]
    fn attestation_is_per_realisation_and_never_alone() {
        let path = Path::new("test.lock");
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let record = |kind: &str| AttestationRecord { kind: kind.into(), root: sri.into(), id: sri.into() };
        let real = |lock: &mut Lock| lock.realisations.get_mut("s").unwrap().get_mut("t").unwrap().clone();
        let set = |lock: &mut Lock, r: LockRealisation| {
            lock.realisations.get_mut("s").unwrap().insert("t".into(), r);
        };

        // In the object's ids: refused, wherever it came from.
        let mut lock = attestable_lock();
        lock.objects.get_mut("k").unwrap().ids.insert("tpm-certify".to_owned(), sri.to_owned());
        let err = lock.validate(path).unwrap_err();
        assert!(err.to_string().contains("belongs to the realisation"), "{err}");

        // On the realisation beside a portable scheme: loads.
        let mut lock = attestable_lock();
        let mut r = real(&mut lock);
        r.attestation = Some(record("tpm-certify"));
        set(&mut lock, r.clone());
        lock.clone().validate(path).unwrap();

        // Alone (a realisation whose portable schemes are gone): refused.
        let mut alone = lock.clone();
        let mut r2 = r.clone();
        r2.schemes.clear();
        set(&mut alone, r2);
        let err = alone.validate(path).unwrap_err();
        assert!(err.to_string().contains("locked only by its attestation"), "{err}");

        // Unknown kind, or a non-SRI id: refused.
        let mut bad = lock.clone();
        let mut r3 = r.clone();
        r3.attestation = Some(record("vendor-x"));
        set(&mut bad, r3);
        assert!(bad.validate(path).unwrap_err().to_string().contains("unknown attestation kind"));
        let mut bad = lock;
        r.attestation.as_mut().unwrap().id = "nope".into();
        set(&mut bad, r);
        assert!(bad.validate(path).unwrap_err().to_string().contains("attestation id"));
    }

    /// A missing lock is an empty one of the current version; what is saved is what loads back,
    /// with no temporary file left beside it; a bare file name lives in the working directory.
    #[test]
    fn a_lock_saves_and_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let empty = load_lock(&path).unwrap();
        assert_eq!((empty.version, empty.objects.len()), (LOCK_VERSION, 0));
        let mut lock =
            load_lock(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"))).unwrap();
        lock.objects.retain(|name, _| lock.realisations.values().any(|r| r.values().any(|r| r.object == *name)));
        save_lock(&path, &lock).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, toml::to_string_pretty(&load_lock(&path).unwrap()).unwrap());
        assert_eq!(load_lock(&path).unwrap().realisations.len(), lock.realisations.len());
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["keys.lock"]);
        assert_eq!(lock_dir(Path::new("keys.lock")), Path::new("."));
        assert_eq!(lock_dir(&path), dir.path());
    }

    /// A lock that exists keeps its mode across a save, exactly and whatever the umask: a 0600
    /// lock stays private, a group's 0660 stays the group's. A key file is never widened by the
    /// file it replaces. A sidecar this user cannot write (another user's, left 0644) still
    /// guards the update: `flock` needs no write access (review 2026-11-23 A-4, A-12).
    #[test]
    fn a_saved_lock_keeps_its_mode_and_a_read_only_sidecar_guards() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        save_lock(&path, &attestable_lock()).unwrap();
        for kept in [0o600, 0o660, 0o640] {
            set(&path, kept);
            save_lock(&path, &attestable_lock()).unwrap();
            assert_eq!(mode(&path), kept, "a save reset the lock's mode");
        }
        let key = dir.path().join("k.pem");
        std::fs::write(&key, "old").unwrap();
        set(&key, 0o644);
        write_whole(&key, b"new", 0o600).unwrap();
        assert_eq!(mode(&key), 0o600, "a key file took the mode of what it replaced");
        let sidecar = dir.path().join("keys.lock.lck");
        std::fs::write(&sidecar, "").unwrap();
        set(&sidecar, 0o444);
        let guard = lock_for_update(&path, |_| unreachable!("nothing else holds it")).unwrap();
        drop(guard);
    }

    /// Why a lock cannot be written: inside a Nix build sandbox, a lock file or a directory this
    /// user cannot write; nothing when both can be (a lock not there yet included).
    #[test]
    fn an_unwritable_lock_says_why() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.lock");
        // What a message names: the path resolved (macOS's /tmp is /private/tmp).
        let real = dir.path().canonicalize().unwrap();
        assert_eq!(unwritable(&path, false), None);
        let sandboxed = unwritable(&path, true).unwrap();
        assert!(sandboxed.contains("inside a Nix build sandbox"), "{sandboxed}");
        std::fs::write(&path, "version = 1\n").unwrap();
        assert_eq!(unwritable(&path, false), None);
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&path, 0o444);
        // access(2) grants root every write: the permission cases mean nothing as root.
        if rustix::fs::access(&path, rustix::fs::Access::WRITE_OK).is_ok() {
            return;
        }
        assert_eq!(unwritable(&path, false), Some(format!("{} is not writable", real.join("keys.lock").display())));
        mode(&path, 0o644);
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert_eq!(said, Some(format!("the lock's directory {} is not writable", real.display())));
        // A lock not there yet in a directory that cannot take it.
        std::fs::remove_file(&path).unwrap();
        mode(dir.path(), 0o555);
        let said = unwritable(&path, false);
        mode(dir.path(), 0o755);
        assert!(said.is_some_and(|s| s.contains("directory")));
    }
}
