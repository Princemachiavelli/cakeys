//! `keys.toml` (input) and `keys.lock` (input, updated in place).
//!
//! Our own keys are camelCase (Nix-friendly); PKCS#11 names (`CKA_*`, `CKO_*`, `CKK_*`) are verbatim.

use crate::error::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub tokens: BTreeMap<String, TokenCfg>,
    #[serde(default)]
    pub objects: BTreeMap<String, ObjectCfg>,
    #[serde(default)]
    pub specs: BTreeMap<String, SpecCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenCfg {
    /// Path to the PKCS#11 module; can be overridden with `--module <token>=<path>`.
    pub module: Option<String>,
    /// Provider crate handling this module's quirks; auto-detected from `C_GetInfo` if unset.
    pub provider: Option<String>,
    pub token_label: String,
    pub pin_file: Option<PathBuf>,
    pub pin_env: Option<String>,
    /// Nix `requiredSystemFeatures` entry; defaults to `token-<name>`. Read by the Nix library.
    #[allow(dead_code)]
    pub system_feature: Option<String>,
}

/// Intrinsic object type: identical across every spec of the object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectCfg {
    pub class: String,
    /// `CKK_*` for keys; certificates use `certificateType = "CKC_X_509"`; data objects have none.
    /// Omitted from the spec digest when empty, so existing digests are unchanged.
    #[serde(default, alias = "certificateType", skip_serializing_if = "String::is_empty")]
    pub key_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Secret key length in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_len: Option<u64>,
    /// RSA modulus size in bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modulus_bits: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCfg {
    pub object: String,
    /// Policy attributes (`CKA_SIGN = true`, ...). Part of the spec digest.
    #[serde(default)]
    pub attributes: BTreeMap<String, bool>,
    pub tokens: BTreeMap<String, SpecTokenCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecTokenCfg {
    pub locator: Locator,
    #[serde(default)]
    pub auto_create: bool,
    /// Adopt a private key through its public key object only (no login needed, e.g. to
    /// spare PIV PIN retries). Identity is fully verified; presence and policy of the private
    /// half are not, so this is an explicit per-token opt-in recorded in the lock.
    #[serde(default)]
    pub public_only: bool,
    #[serde(default)]
    pub identity: IdentityCfg,
}

/// Arbitrary user values naming the object on one token. Not part of the spec digest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    #[serde(rename = "CKA_LABEL")]
    pub label: Option<String>,
    /// Hex-encoded.
    #[serde(rename = "CKA_ID")]
    pub id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCfg {
    /// Weak identity modes explicitly allowed on this token.
    #[serde(default)]
    pub allow: Vec<Mode>,
}

/// Identity modes, strongest first (see PLAN.md, "Per-token identity modes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Direct,
    Commitment,
    WrapRebind,
    CommitAtCreation,
    HostAtImport,
    TokenSpecific,
}

impl Mode {
    pub fn needs_opt_in(self) -> bool {
        self > Mode::WrapRebind
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.as_str().unwrap_or_default())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    #[serde(default = "lock_version")]
    pub version: u32,
    #[serde(default)]
    pub objects: BTreeMap<String, LockObject>,
    /// spec name -> token name -> realisation
    #[serde(default)]
    pub realisations: BTreeMap<String, BTreeMap<String, LockRealisation>>,
}

fn lock_version() -> u32 {
    LOCK_VERSION
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockObject {
    /// Label the object's commitment schemes were computed with. Required whenever
    /// `ids` holds a commitment scheme; verification uses it, never the code default.
    #[serde(default, rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The object type the IDs were computed for (required with `ids`). A `keys.toml` whose type
    /// differs is refused rather than reported as a hash mismatch.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub object_type: Option<ObjectCfg>,
    /// Material CA-IDs: scheme -> SRI hash.
    #[serde(default)]
    pub ids: BTreeMap<String, String>,
}

impl LockObject {
    fn has_commitments(&self) -> bool {
        self.ids.keys().any(|s| crate::id::COMMITMENT_SCHEMES.contains(&s.as_str()))
    }
}

/// The lock format version. Unpublished, so its schema changes in place.
pub const LOCK_VERSION: u32 = 1;

impl Lock {
    /// Refuse other versions, and objects with commitment IDs but no label.
    fn validate(self, path: &Path) -> Result<Lock> {
        if self.version != LOCK_VERSION {
            return Err(KmError::Validation(format!(
                "{}: lock version {} is not supported (this cakeys reads {LOCK_VERSION})",
                path.display(),
                self.version
            )));
        }
        if let Some((name, _)) = self.objects.iter().find(|(_, o)| o.has_commitments() && o.commitment_label.is_none()) {
            return Err(KmError::Validation(format!(
                "{}: object '{name}' has commitment IDs but no commitmentLabel",
                path.display()
            )));
        }
        if let Some((name, _)) = self.objects.iter().find(|(_, o)| !o.ids.is_empty() && o.object_type.is_none()) {
            return Err(KmError::Validation(format!(
                "{}: object '{name}' has IDs but no type",
                path.display()
            )));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LockRealisation {
    pub spec_digest: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub public_only: bool,
    pub uri: String,
    /// PKCS#11 module that realised this (C_GetInfo, plus the loaded file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleInfo>,
    /// Token that holds it (C_GetTokenInfo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,
    /// Provider that handled the module (provenance: fix-ups must not change identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// cakeys version that realised it (provenance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cakeys_version: Option<String>,
    /// Token mechanisms observed at realisation time (for `functions.<token>`).
    #[serde(default)]
    pub mechanisms: Vec<String>,
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| KmError::Validation(format!("{}: {e}", path.display())).into())
}

pub fn load_lock(path: &Path) -> anyhow::Result<Lock> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let lock: Lock = toml::from_str(&text)
                .map_err(|e| KmError::Validation(format!("{}: {e}", path.display())))?;
            Ok(lock.validate(path)?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Lock {
            version: LOCK_VERSION,
            ..Default::default()
        }),
        Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

pub fn save_lock(path: &Path, lock: &Lock) -> anyhow::Result<()> {
    let text = toml::to_string_pretty(lock)?;
    let tmp = path.with_extension("lock.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

impl Config {
    /// Find the spec to use for `object` on `token` (either may be omitted if unambiguous).
    pub fn pick_spec(
        &self,
        object: &str,
        spec: Option<&str>,
        token: Option<&str>,
    ) -> Result<(String, String)> {
        let pairs: Vec<(String, String)> = self
            .specs
            .iter()
            .filter(|(n, s)| s.object == object && spec.is_none_or(|w| w == n.as_str()))
            .flat_map(|(n, s)| s.tokens.keys().map(move |t| (n.clone(), t.clone())))
            .filter(|(_, t)| token.is_none_or(|w| w == t))
            .collect();
        match pairs.len() {
            1 => Ok(pairs.into_iter().next().unwrap()),
            0 => Err(KmError::NotFound(format!(
                "no spec for object '{object}' on token {token:?}"
            ))),
            _ => Err(KmError::Ambiguous(format!(
                "object '{object}' has several (spec, token) pairs {pairs:?}; pass --spec/--token"
            ))),
        }
    }
}

/// Module that realised an object (`C_GetInfo` plus the loaded file). Provenance only: on verify a
/// different build identity is a warning and a different `path` alone is a note; identity itself
/// is enforced by the CA-IDs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    pub path: String,
    pub description: String,
    pub manufacturer: String,
    pub version: String,
    pub cryptoki: String,
}

impl ModuleInfo {
    /// Equal apart from `path`.
    pub fn same_build_identity(&self, other: &Self) -> bool {
        (&self.description, &self.manufacturer, &self.version, &self.cryptoki)
            == (&other.description, &other.manufacturer, &other.version, &other.cryptoki)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInfo {
    pub model: String,
    pub serial: String,
    pub firmware: String,
}
