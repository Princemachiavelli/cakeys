//! `keys.toml` (input) and `keys.lock` (input, updated in place).
//!
//! Our own keys are camelCase (Nix-friendly); PKCS#11 names (`CKA_*`, `CKO_*`, `CKK_*`) are verbatim.

use crate::error::{KmError, Result};
use crate::types::{KeyType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod address;
mod check;
mod io;
mod lock;
mod observe;
pub(crate) use check::is_name;
use check::{
    check_names, check_origins, check_scratch_slots, check_secret_files, check_token, check_transport_keys,
    check_value_len, env_ref,
};
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
    cfg: &'a ObjectCfg,
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

impl std::ops::Deref for Object<'_> {
    type Target = ObjectCfg;

    fn deref(&self) -> &ObjectCfg {
        self.cfg
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
