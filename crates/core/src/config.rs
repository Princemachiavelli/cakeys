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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenCfg {
    /// Path to the PKCS#11 module; can be overridden with `--module <token>=<path>`.
    pub module: Option<String>,
    /// Provider crate handling this module's quirks; auto-detected from `C_GetInfo` if unset.
    pub provider: Option<String>,
    pub token_label: String,
    pub pin_file: Option<PathBuf>,
    pub pin_env: Option<String>,
    /// The admin (Security Officer) credential, for modules that create and destroy objects only
    /// in an SO session — ykcs11: the PIV management key in hex, or the PIN on a device whose
    /// management key is PIN-protected. `pinFile`/`pinEnv` remain the *user* credential. Read
    /// just before such a step, never by `resolve`, `verify` or `check`; the user session is
    /// restored afterwards, so a user PIN is required. `mgmKeyEnv` wins if both are set;
    /// `mgmKeyFile` may be `$NAME`, like `pinFile`. Refused on a provider that does not need it.
    pub mgm_key_file: Option<PathBuf>,
    pub mgm_key_env: Option<String>,
    /// Nix `requiredSystemFeatures` entry; defaults to `token-<name>`. Read by the Nix library.
    #[allow(dead_code)]
    pub system_feature: Option<String>,
    /// tpm2-pkcs11 only: TCTI connection string for the native attestation path (TPM2_Certify),
    /// in tss-esapi `TctiNameConf` syntax (`"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`)
    /// or a TCTI library name (`"libtss2-tcti-tabrmd.so.0:bus_type=session"`). Defaults to the
    /// module's own `$TPM2_PKCS11_TCTI`, then `$TPM2TOOLS_TCTI`, then `$TCTI`.
    pub tcti: Option<String>,
    /// tpm2-pkcs11 only: directory of the sqlite store backing the module, read (read-only) by
    /// the native attestation path to find the object's TPM blobs. Defaults to the store
    /// tpm2-pkcs11 itself opens: `$TPM2_PKCS11_STORE`, else the first of `/etc/tpm2_pkcs11`,
    /// `$XDG_DATA_HOME/tpm2-pkcs11` (`~/.local/share/tpm2-pkcs11`), `~/.tpm2_pkcs11` and the
    /// working directory that holds `tpm2_pkcs11.sqlite3`.
    pub tpm2_store: Option<String>,
    /// tpm2-pkcs11 only: persistent handle of cakeys' Attestation Key (a restricted signing key
    /// in the owner hierarchy, created by `realise` if absent, empty auth, and pinned in the
    /// lock by the `attestation.root` of the realisation). Defaults to the provider's
    /// `DEFAULT_AK_HANDLE`; `0x`-prefixed hex in 0x81000000..=0x817FFFFF, e.g. `"0x81000016"`.
    /// An object already there that is not such a key is refused (13).
    pub ak_handle: Option<String>,
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

/// Inline-table form, as keys.toml writes it.
impl std::fmt::Display for ObjectCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![format!("class = {:?}", self.class)];
        if !self.key_type.is_empty() {
            fields.push(format!("keyType = {:?}", self.key_type));
        }
        fields.extend(self.certificate_type.as_ref().map(|c| format!("certificateType = {c:?}")));
        fields.extend(self.curve.as_ref().map(|c| format!("curve = {c:?}")));
        fields.extend(self.value_len.map(|n| format!("valueLen = {n}")));
        fields.extend(self.modulus_bits.map(|n| format!("modulusBits = {n}")));
        write!(f, "{{ {} }}", fields.join(", "))
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
    /// Opt in to the attestation commitment (§3.7 of docs/DESIGN.md): compute the provider's
    /// attestation scheme for this key on this token (YubiKey PIV attestation verified to the
    /// pinned Yubico root; a native `TPM2_Certify` for tpm2-pkcs11) and require it ever after —
    /// a realisation that stops computing it is a scheme downgrade (exit 14). The attestation
    /// ID never replaces the portable one: it is recorded only beside `rfc7093m4` (keys) or a
    /// commitment scheme (secret keys), which is what verifies the same material copied to
    /// another token, where no attestation can exist.
    #[serde(default)]
    pub attestation: bool,
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
            // Attestation IDs are per device (§3.7): the same material attested on two TPMs has
            // two IDs, so they live on each realisation, never in the object's shared `ids`.
            if let Some(s) = o.ids.keys().find(|s| crate::id::is_attestation_scheme(s)) {
                return invalid(format!(
                    "object '{name}' records the attestation scheme {s}: an attestation ID is per device \
                     and belongs to the realisation that computed it (realisations.<spec>.<token>.attestation)"
                ));
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
                // Attestation evidence (§3.7): a known kind, SRI digests, and never alone — the
                // realisation must also have matched a portable scheme, the only thing that links
                // the same material on another token.
                if let Some(a) = &r.attestation {
                    if crate::id::attestation_scheme_of(&a.kind).is_none() {
                        return invalid(format!(
                            "realisation of '{spec}' on '{token}': unknown attestation kind '{}' (known: {:?})",
                            a.kind,
                            crate::id::ATTESTATION_KINDS.map(|(_, k)| k)
                        ));
                    }
                    if let Some((field, v)) = [("root", &a.root), ("id", &a.id)].into_iter().find(|(_, v)| !crate::id::is_sri(v)) {
                        return invalid(format!(
                            "realisation of '{spec}' on '{token}': attestation {field} \"{v}\" is not a sha256 SRI digest"
                        ));
                    }
                    if r.schemes.is_empty() {
                        return invalid(format!(
                            "realisation of '{spec}' on '{token}' is locked only by its attestation: an \
                             attestation is provenance for one device and cannot verify the same material \
                             on another token; it needs a portable scheme (rfc7093m4, or a commitment for \
                             secret keys) beside it"
                        ));
                    }
                }
            }
        }
        Ok(self)
    }

    /// The realisation of `spec` on `token`, if the lock records one.
    pub fn realisation(&self, spec: &str, token: &str) -> Option<&LockRealisation> {
        self.realisations.get(spec)?.get(token)
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
    /// The attestation this realisation pinned (§3.7 of docs/DESIGN.md), when its spec opted in:
    /// the per-device attestation ID and the *anchor* it was verified against — the Yubico root
    /// (PIV) or the Attestation Key (TPM). Kept here, not in `objects.<name>.ids`: the same
    /// material attested on two devices has two IDs, joined through the portable `schemes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
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

/// Offline-verifiable attestation evidence pinned per realisation (§3.7 of docs/DESIGN.md).
/// `kind` names the attestation (`yubico-piv`, `tpm-certify` — one per scheme, see
/// `id::ATTESTATION_KINDS`), `root` is the SRI digest of the trust anchor the chain was verified
/// to: the pinned Yubico root's SPKI for PIV (never the device's own overwritable slot f9), or
/// the Attestation Key's SPKI for TPM. `id` is the attestation commitment of this device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttestationRecord {
    pub kind: String,
    pub root: String,
    pub id: String,
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

    fn fields(&self) -> Vec<String> {
        let flag = |n: &str, v: Option<bool>| v.map(|b| format!("{n} = {b}"));
        [
            flag("CKA_LOCAL", self.local),
            flag("CKA_NEVER_EXTRACTABLE", self.never_extractable),
            flag("CKA_ALWAYS_SENSITIVE", self.always_sensitive),
            self.key_gen_mechanism.as_ref().map(|m| format!("CKA_KEY_GEN_MECHANISM = {m:?}")),
        ]
        .into_iter()
        .flatten()
        .collect()
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

/// Inline-table form, as the lock writes it.
impl std::fmt::Display for Immutables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {} }}", self.fields().join(", "))
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
/// file, cakeys version); `realise` re-binds them.
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
    for (name, t) in &mut cfg.tokens {
        if let Some(m) = t.module.clone() {
            t.module = Some(env_ref(&m, &format!("token '{name}': module"))?);
        }
        if let Some(p) = t.pin_file.clone() {
            let expanded = env_ref(&p.to_string_lossy(), &format!("token '{name}': pinFile"))?;
            t.pin_file = Some(PathBuf::from(expanded));
        }
        if let Some(m) = t.mgm_key_file.clone() {
            let expanded = env_ref(&m.to_string_lossy(), &format!("token '{name}': mgmKeyFile"))?;
            t.mgm_key_file = Some(PathBuf::from(expanded));
        }
        // An SO step logs the user out; without a user PIN to return to, the new private key
        // could not be found again, let alone proven.
        if (t.mgm_key_file.is_some() || t.mgm_key_env.is_some()) && t.pin_file.is_none() && t.pin_env.is_none() {
            return Err(KmError::Validation(format!(
                "{}: token '{name}': mgmKeyFile/mgmKeyEnv needs a user PIN (pinFile or pinEnv) to return to the user session",
                path.display()
            ))
            .into());
        }
    }
    // A spec's object reference must name something, also when no token ever uses the spec.
    for (spec, s) in &cfg.specs {
        if !cfg.objects.contains_key(&s.object) {
            return Err(KmError::Validation(format!(
                "{}: spec '{spec}' references unknown object '{}'",
                path.display(),
                s.object
            ))
            .into());
        }
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

/// A whole-value environment reference in a path field: `$NAME` or `${NAME}` becomes the value of
/// the environment variable `NAME` when the config is loaded, so one shared `keys.toml` can carry
/// a machine-specific pin file or module path. A value with no leading `$` is a literal path; a
/// malformed or unset reference fails at load (exit 17), naming it — not at login time.
fn env_ref(value: &str, what: &str) -> anyhow::Result<String> {
    let name = match value.strip_prefix('$') {
        Some(rest) => rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(rest),
        None => return Ok(value.to_owned()),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(KmError::Validation(format!(
            "{what}: \"{value}\" is neither $NAME, ${{NAME}} nor a literal path"
        ))
        .into());
    }
    std::env::var(name).map_err(|_| {
        KmError::Validation(format!("{what}: environment variable {name} (\"{value}\") is not set")).into()
    })
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

/// The advisory lock held around the lock file's read-modify-write (finding M3). A run that may
/// update the lock takes it before `load_lock` and drops it after `save_lock`, so two concurrent
/// runs on different tokens cannot lose each other's realisations. Readers never take it: the
/// temporary-file rename makes each read a consistent snapshot.
pub struct UpdateGuard(#[allow(dead_code)] std::fs::File); // holds the lock until dropped

/// Take the exclusive advisory lock on `<lock>.lck`, waiting for any other updater. The sidecar
/// file is created if absent; a leftover one is harmless (the lock is advisory and released when
/// its holder exits).
pub fn lock_for_update(lock_path: &Path) -> anyhow::Result<UpdateGuard> {
    let mut sidecar = lock_path.as_os_str().to_os_string();
    sidecar.push(".lck");
    let file = std::fs::File::options().write(true).create(true).truncate(false).open(&sidecar)?;
    file.lock().map_err(|e| anyhow::anyhow!("locking {}: {e}", sidecar.to_string_lossy()))?;
    Ok(UpdateGuard(file))
}

/// Why this run cannot write the lock at `lock_path`, if it cannot. A run that writes by default
/// (`realise`, `delete`) asks before it touches a token, so an unwritable lock is a refusal up
/// front — never a key created and then not recorded — unless `--no-update-lock` was passed.
/// - Inside a Nix build sandbox (`NIX_BUILD_TOP` set, `IN_NIX_SHELL` not: `nix develop` sets
///   both) a write is lost: the lock is a read-only store path, or a copy thrown away with the
///   build.
/// - Otherwise the lock file, if present, and its directory (temporary file, rename and the
///   `.lck` sidecar) must be writable by this user (`access(2)`, so a read-only mount counts).
pub fn lock_unwritable(lock_path: &Path) -> Option<String> {
    if std::env::var_os("NIX_BUILD_TOP").is_some() && std::env::var_os("IN_NIX_SHELL").is_none() {
        return Some("this run is inside a Nix build sandbox, where a lock write would be lost".into());
    }
    let writable = |p: &Path| {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(p.as_os_str().as_bytes())
            // SAFETY: a valid NUL-terminated path; access(2) only reads it.
            .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0)
    };
    if lock_path.exists() && !writable(lock_path) {
        return Some(format!("{} is not writable", lock_path.display()));
    }
    let dir = lock_path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !writable(dir) {
        return Some(format!("the lock's directory {} is not writable", dir.display()));
    }
    None
}

/// Lock entries `cfg` no longer names (finding D3): every `[realisations.<spec>.<token>]` whose
/// spec or token is gone from keys.toml, and every `[objects.<name>]` absent from it — printed by
/// `gc` as table names, removed with `--apply`. Live objects keep their `ids` however few specs
/// use them; only entries whose whole subject is gone are collected. With `remove`, exactly the
/// returned entries are dropped.
pub fn gc(cfg: &Config, lock: &mut Lock, remove: bool) -> Vec<String> {
    let mut stale = Vec::new();
    for (spec, tokens) in &lock.realisations {
        let gone = |t: &&String| match cfg.specs.get(spec) {
            None => true,
            Some(s) => !s.tokens.contains_key(*t),
        };
        stale.extend(tokens.keys().filter(gone).map(|t| format!("realisations.{spec}.{t}")));
    }
    stale.extend(
        lock.objects
            .keys()
            .filter(|o| !cfg.objects.contains_key(*o))
            .map(|o| format!("objects.{o}")),
    );
    if remove {
        let mut empty = Vec::new();
        for (spec, tokens) in &mut lock.realisations {
            tokens.retain(|t, _| match cfg.specs.get(spec) {
                None => false,
                Some(s) => s.tokens.contains_key(t),
            });
            if tokens.is_empty() {
                empty.push(spec.clone());
            }
        }
        for spec in empty {
            lock.realisations.remove(&spec);
        }
        lock.objects.retain(|o, _| cfg.objects.contains_key(o));
    }
    stale
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

    /// `$NAME`/`${NAME}` in `pinFile` and `module` read the path from the environment; an unset or
    /// malformed reference is invalid at load (17), and a spec must reference an existing object.
    #[test]
    fn env_references_and_object_refs_are_checked_at_load() {
        let dir = std::env::temp_dir().join("cakeys-load-config-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let load = |body: &str| {
            let p = dir.join("keys.toml");
            std::fs::write(&p, body).unwrap();
            load_config(&p)
        };
        let head = "[tokens.t]\ntokenLabel = \"x\"\n";
        // A literal path loads as-is; $NAME and ${NAME} expand.
        assert_eq!(
            load(&format!("{head}pinFile = \"/literal/pin\"\n")).unwrap().tokens["t"].pin_file,
            Some(PathBuf::from("/literal/pin"))
        );
        std::env::set_var("KM_UNIT_TEST_PIN", "/env/pin");
        let cfg = load(&format!("{head}pinFile = \"$KM_UNIT_TEST_PIN\"\nmodule = \"${{KM_UNIT_TEST_PIN}}\"\n")).unwrap();
        std::env::remove_var("KM_UNIT_TEST_PIN");
        assert_eq!(cfg.tokens["t"].pin_file, Some(PathBuf::from("/env/pin")));
        assert_eq!(cfg.tokens["t"].module.as_deref(), Some("/env/pin"));
        // An unset variable fails at load, naming it; so does a malformed reference.
        let err = load(&format!("{head}pinFile = \"$KM_UNIT_TEST_UNSET\"\n")).unwrap_err();
        assert!(err.to_string().contains("KM_UNIT_TEST_UNSET"), "{err}");
        let err = load(&format!("{head}pinFile = \"$HOME/x\"\n")).unwrap_err();
        assert!(err.to_string().contains("neither $NAME"), "{err}");
        // mgmKeyFile expands the same way; an admin credential only comes with a user PIN.
        std::env::set_var("KM_UNIT_TEST_MGM", "/env/mgm");
        let cfg = load(&format!("{head}pinFile = \"/p\"\nmgmKeyFile = \"$KM_UNIT_TEST_MGM\"\n")).unwrap();
        std::env::remove_var("KM_UNIT_TEST_MGM");
        assert_eq!(cfg.tokens["t"].mgm_key_file, Some(PathBuf::from("/env/mgm")));
        for admin in ["mgmKeyFile = \"/so\"", "mgmKeyEnv = \"SO\""] {
            let err = load(&format!("{head}{admin}\n")).unwrap_err();
            assert!(err.to_string().contains("needs a user PIN"), "{err}");
        }
        // A spec's object reference must exist, also when nothing uses the spec.
        let err = load(&format!(
            "{head}\n[objects.o]\nclass = \"CKO_DATA\"\n\n[specs.s]\nobject = \"missing\"\ntokens = {{}}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown object 'missing'"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
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

    /// A minimal valid lock with one object and realisation, for the attestation-invariant
    /// tests: the caller mutates it and expects `validate` to accept or refuse.
    fn attestable_lock() -> Lock {
        let mut ids = BTreeMap::new();
        ids.insert("rfc7093m4".to_owned(), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_owned());
        let mut lock = Lock {
            version: LOCK_VERSION,
            ..Default::default()
        };
        lock.objects.insert(
            "k".into(),
            LockObject {
                object_type: Some(ObjectCfg { class: "CKO_PRIVATE_KEY".into(), key_type: "CKK_EC".into(), curve: Some("secp256r1".into()), ..Default::default() }),
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
}
