//! `keys.toml` (input) and `keys.lock` (input, updated in place).
//!
//! Our own keys are camelCase (Nix-friendly); PKCS#11 names (`CKA_*`, `CKO_*`, `CKK_*`) are verbatim.

use crate::error::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectCfg {
    pub class: String,
    /// `CKK_*` for keys; empty (and omitted) for certificates and data objects.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_type: String,
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
    /// Replace a curve alias by its canonical name (unknown names are left for validation).
    pub fn canonicalize(&mut self) {
        if let Some(c) = self.curve.as_deref().and_then(|c| crate::id::Curve::from_cfg(&self.key_type, c)) {
            self.curve = Some(c.name().to_owned());
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCfg {
    pub object: String,
    /// Policy attributes of the object (`CKA_SIGN = true`, `CKA_ALLOWED_MECHANISMS = [...]`).
    /// Part of the spec digest.
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrValue>,
    /// Policy attributes of a private key's public key object (`CKA_VERIFY = true`, ...): set
    /// when generating, checked on the public object. In the spec digest only when present.
    #[serde(default, rename = "publicAttributes")]
    pub public_attributes: BTreeMap<String, AttrValue>,
    pub tokens: BTreeMap<String, SpecTokenCfg>,
}

impl SpecCfg {
    /// A declared boolean attribute.
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.attributes.get(name) {
            Some(AttrValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// A policy attribute value: a boolean, or a set of `CKM_*` names (`CKA_ALLOWED_MECHANISMS`),
/// kept sorted and without duplicates so its order never changes a digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AttrValue {
    Bool(bool),
    Mechanisms(Vec<String>),
}

impl AttrValue {
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
    /// `"token-asserted"`: do not prove possession of the private key, for keys that cannot sign
    /// anything the host can verify. Recorded in the lock; `publicOnly` implies it.
    #[serde(default)]
    pub binding: Option<Binding>,
}

/// Arbitrary user values naming the object on one token. Not part of the spec digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    #[serde(rename = "CKA_LABEL", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Hex-encoded.
    #[serde(rename = "CKA_ID", skip_serializing_if = "Option::is_none")]
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

/// How a private-key object is bound to the public key its identity hashes (docs/DESIGN.md §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Binding {
    /// The token signed a fresh challenge that verified on the host against that public key.
    PopSign,
    /// The token derived the ECDH shared secret with an ephemeral host key and both sides MACed
    /// the challenge with it (derive-only EC keys).
    PopEcdh,
    /// The token decrypted a host challenge (RSA-OAEP) to the expected plaintext (decrypt-only
    /// RSA keys).
    PopDecrypt,
    /// Only the token says the objects belong together (opt-in, or `publicOnly`).
    TokenAsserted,
}

impl Binding {
    /// Strength, strongest 0: a realisation must never move to a higher rank. Every `pop-*`
    /// proves the same fact — possession of the named public key — by whichever capability the
    /// key has.
    pub fn rank(self) -> u8 {
        match self {
            Binding::PopSign | Binding::PopEcdh | Binding::PopDecrypt => 0,
            Binding::TokenAsserted => 1,
        }
    }
}

impl std::fmt::Display for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.as_str().unwrap_or_default())
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
    pub version: u32,
    #[serde(default)]
    pub objects: BTreeMap<String, LockObject>,
    /// spec name -> token name -> realisation
    #[serde(default)]
    pub realisations: BTreeMap<String, BTreeMap<String, LockRealisation>>,
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
    /// Other objects with the same public key (`rfc7093m4`): a key and its certificate, a private
    /// and a public key object. Recorded by cakeys, symmetric, and checked on load.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pairs: BTreeSet<String>,
}

impl LockObject {
    fn has_commitments(&self) -> bool {
        self.ids.keys().any(|s| crate::id::COMMITMENT_SCHEMES.contains(&s.as_str()))
    }
}

/// The lock format version. Unpublished, so its schema changes in place.
pub const LOCK_VERSION: u32 = 1;

impl Lock {
    /// Refuse other versions (the version is required), and objects with commitment IDs but no
    /// label.
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
        for (name, o) in &self.objects {
            if let Some((alias, scheme)) = crate::id::SCHEME_ALIASES.iter().find(|(a, _)| o.ids.contains_key(*a)) {
                return Err(KmError::Validation(format!(
                    "{}: object '{name}' records '{alias}', which is an input alias; the lock uses '{scheme}'",
                    path.display()
                )));
            }
        }
        if let Some((name, _)) = self.objects.iter().find(|(_, o)| !o.ids.is_empty() && o.object_type.is_none()) {
            return Err(KmError::Validation(format!(
                "{}: object '{name}' has IDs but no type",
                path.display()
            )));
        }
        let invalid = |msg: String| Err(KmError::Validation(format!("{}: {msg}", path.display())));
        for (name, o) in &self.objects {
            if let Some((s, v)) = o.ids.iter().find(|(_, v)| !crate::id::is_sri(v)) {
                return invalid(format!("object '{name}': {s} = \"{v}\" is not a sha256 SRI digest"));
            }
            if let Some(l) = o.commitment_label.as_ref().filter(|l| l.is_empty() || !l.bytes().all(|b| b.is_ascii_graphic() || b == b' ')) {
                return invalid(format!("object '{name}': commitmentLabel {l:?} must be non-empty printable ASCII"));
            }
        }
        for (spec, by_token) in &self.realisations {
            for (token, r) in by_token {
                let what = format!("realisation of '{spec}' on '{token}'");
                if !crate::id::is_sri(&r.spec_digest) {
                    return invalid(format!("{what}: specDigest \"{}\" is not a sha256 SRI digest", r.spec_digest));
                }
                let Some(o) = self.objects.get(&r.object) else {
                    return invalid(format!("{what}: object '{}' is not in the lock", r.object));
                };
                if let Some(s) = r.schemes.iter().find(|s| !o.ids.contains_key(*s)) {
                    return invalid(format!("{what}: scheme {s} is not among the IDs of '{}'", r.object));
                }
            }
        }
        // One object per material: two objects of one class with the same ID are the same thing
        // under two names. A certificate's rfc7093m4 names its subject key, which several
        // certificates may share.
        let mut seen: BTreeMap<(&str, &str, &str), &str> = BTreeMap::new();
        for (name, o) in &self.objects {
            let class = o.object_type.as_ref().map_or("", |t| t.class.as_str());
            for (s, v) in o.ids.iter().filter(|(s, _)| !(class == "CKO_CERTIFICATE" && *s == "rfc7093m4")) {
                if let Some(other) = seen.insert((s, class, v), name) {
                    return invalid(format!(
                        "objects '{other}' and '{name}' are the same {class} material ({s} {v}); use one object"
                    ));
                }
            }
        }
        // A listed partner that is in this file must share the public key and list back; one
        // that is not may live in another lock fragment (locks can be split and joined).
        for (name, o) in &self.objects {
            for p in &o.pairs {
                if p == name {
                    return invalid(format!("object '{name}' lists itself as a pair"));
                }
                let Some(other) = self.objects.get(p) else { continue };
                let shared = o.ids.get("rfc7093m4").is_some_and(|k| other.ids.get("rfc7093m4") == Some(k));
                if !shared || !other.pairs.contains(name) {
                    return invalid(format!(
                        "object '{name}' lists '{p}' as a pair, but they {}",
                        if shared { "do not list each other" } else { "do not share an rfc7093m4" }
                    ));
                }
            }
        }
        for (spec, by_token) in &self.realisations {
            for (token, r) in by_token {
                let private = self.objects[&r.object].object_type.as_ref().is_some_and(|t| t.class == "CKO_PRIVATE_KEY");
                if private != r.binding.is_some() {
                    return invalid(format!(
                        "realisation of '{spec}' on '{token}': binding is {} for private keys and only for them",
                        if private { "required" } else { "allowed" }
                    ));
                }
            }
        }
        Ok(self)
    }

    /// Objects in this file that share an rfc7093m4 with `name` but are not listed as its pairs.
    pub fn unlisted_pairs(&self, name: &str) -> BTreeSet<String> {
        let listed = self.objects.get(name).map(|o| &o.pairs);
        self.computed_pairs()
            .remove(name)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| listed.is_none_or(|l| !l.contains(p)))
            .collect()
    }

    /// For every object, the other objects with the same public key (`rfc7093m4`).
    pub fn computed_pairs(&self) -> BTreeMap<String, BTreeSet<String>> {
        let key = |o: &LockObject| o.ids.get("rfc7093m4").cloned();
        self.objects
            .iter()
            .filter_map(|(name, o)| {
                let k = key(o)?;
                let others: BTreeSet<String> = self
                    .objects
                    .iter()
                    .filter(|(n, p)| *n != name && key(p).as_ref() == Some(&k))
                    .map(|(n, _)| n.clone())
                    .collect();
                (!others.is_empty()).then(|| (name.clone(), others))
            })
            .collect()
    }
}

/// One realisation of a spec on a token. Fields fall in three classes (docs/DESIGN.md §4.2):
/// - **compared** (top level): verification fails when they differ from keys.toml or the token;
/// - **`observed`**: recorded facts about the token that never change a verdict;
/// - **`provenance`**: what produced the record; differences only warn.
///
/// Stripping `observed` and `provenance` from a lock never changes a verdict.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LockRealisation {
    /// The object this spec realised and the locator it was found under: a spec pointed at
    /// another object or locator in keys.toml is a change to review, not a hash mismatch.
    pub object: String,
    pub locator: Locator,
    pub spec_digest: String,
    pub mode: Mode,
    /// The identity schemes this realisation computed and matched: computing fewer later is a
    /// downgrade. Also shows which realisation established which locked ID.
    pub schemes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub public_only: bool,
    /// Private keys: how the private object is bound to the identity. Absent: not recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// Every boolean attribute the object exposes for its class (`CKA_SIGN = true`, ...), as
    /// read from the token: declared or not. A drift is a change to review.
    pub policy: BTreeMap<String, AttrValue>,
    /// Attributes fixed when the object was made; one that weakens means it was replaced.
    #[serde(default, skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<Observed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

/// Key attributes the token sets when the key is made, which no later operation can restore
/// (PKCS#11 3.2 §4.9-4.10): `true` → `false` means the object was replaced, e.g. re-imported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Immutables {
    #[serde(rename = "CKA_LOCAL", default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    #[serde(rename = "CKA_NEVER_EXTRACTABLE", default, skip_serializing_if = "Option::is_none")]
    pub never_extractable: Option<bool>,
    #[serde(rename = "CKA_ALWAYS_SENSITIVE", default, skip_serializing_if = "Option::is_none")]
    pub always_sensitive: Option<bool>,
    /// `CKM_...`, absent when the token reports none (an imported key).
    #[serde(rename = "CKA_KEY_GEN_MECHANISM", default, skip_serializing_if = "Option::is_none")]
    pub key_gen_mechanism: Option<String>,
}

impl Immutables {
    pub fn is_empty(&self) -> bool {
        *self == Immutables::default()
    }

    /// Flags that were `true` when recorded and are not now.
    pub fn weakened_since(&self, recorded: &Immutables) -> Vec<&'static str> {
        [
            ("CKA_LOCAL", recorded.local, self.local),
            ("CKA_NEVER_EXTRACTABLE", recorded.never_extractable, self.never_extractable),
            ("CKA_ALWAYS_SENSITIVE", recorded.always_sensitive, self.always_sensitive),
        ]
        .into_iter()
        .filter(|(_, was, now)| *was == Some(true) && *now != Some(true))
        .map(|(n, _, _)| n)
        .collect()
    }
}

/// Facts about the token at realisation time. Never compared.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Observed {
    /// RFC 7512 URI of the object (derived from the token label, serial and locator).
    pub uri: String,
    /// `user` (logged in: private objects and duplicate private-key IDs were visible) or `public`.
    pub session: String,
    /// Usable mechanisms (feeds `functions.<token>` in the Nix library). One that has since gone
    /// from the token is a warning.
    #[serde(default)]
    pub mechanisms: Vec<String>,
}

/// What produced the record. Differences warn (module build, token, provider) or note (module
/// file, cakeys version); `realise --update-lock` re-binds them.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Provenance {
    /// Provider that handled the module (fix-ups must not change identity).
    pub provider: String,
    pub cakeys_version: String,
    /// PKCS#11 module (C_GetInfo, plus the loaded file).
    pub module: ModuleInfo,
    /// Token that holds the object (C_GetTokenInfo).
    pub token: TokenInfo,
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&text).map_err(|e| KmError::Validation(format!("{}: {e}", path.display())))?;
    for o in cfg.objects.values_mut() {
        o.canonicalize();
    }
    for s in cfg.specs.values_mut() {
        for v in s.attributes.values_mut().chain(s.public_attributes.values_mut()) {
            if let AttrValue::Mechanisms(m) = v {
                *v = AttrValue::mechanisms(std::mem::take(m));
            }
        }
    }
    Ok(cfg)
}

pub fn load_lock(path: &Path) -> anyhow::Result<Lock> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let mut lock: Lock = toml::from_str(&text)
                .map_err(|e| KmError::Validation(format!("{}: {e}", path.display())))?;
            // Recorded types compare equal to canonicalized keys.toml types.
            for t in lock.objects.values_mut().filter_map(|o| o.object_type.as_mut()) {
                t.canonicalize();
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic Nix-library fixture must stay a valid lock of the current schema.
    #[test]
    fn fixture_lock_parses() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"));
        let lock = load_lock(path).unwrap();
        assert_eq!(lock.realisations["signing-soft"]["softhsm"].binding, Some(Binding::PopSign));
    }

    /// Downgrade detection compares ranks: an inverted order would silently disable it. The
    /// `pop-*` methods share rank 0: each proves possession of the same key.
    #[test]
    fn binding_ranks_are_pinned() {
        assert!(Binding::PopSign.rank() < Binding::TokenAsserted.rank());
        assert_eq!(Binding::PopSign.to_string(), "pop-sign");
        assert_eq!(Binding::PopEcdh.to_string(), "pop-ecdh");
        assert_eq!(Binding::PopDecrypt.to_string(), "pop-decrypt");
        assert_eq!(Binding::PopEcdh.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::PopDecrypt.rank(), Binding::PopSign.rank());
        assert_eq!(Binding::TokenAsserted.to_string(), "token-asserted");
    }
}
