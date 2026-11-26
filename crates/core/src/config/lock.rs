//! The `keys.lock` file: which objects were realised on which tokens, the invariants that every
//! lock must meet, and `gc`.

use super::{AttrValue, Config, Locator, ObjectCfg, Observation, Observed, Provenance, TokenObservation};
use crate::error::{KmError, Result};
use crate::id::Scheme;
use crate::known::{Known, Why};
use crate::types::ObjectClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A parsed `keys.lock` file (docs/LOCK.md): the IDs of each object and the realisations of each
/// spec, as cakeys recorded them.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    /// The version of the lock format. The load refuses a lock with any version other than
    /// [`LOCK_VERSION`].
    pub version: u32,
    /// The identity of each object, keyed by the object name.
    #[serde(default)]
    pub objects: BTreeMap<String, LockObject>,
    /// The realisations, keyed first by the spec name and then by the token name.
    #[serde(default)]
    pub realisations: BTreeMap<String, BTreeMap<String, LockRealisation>>,
    /// What the realisations saw of their tokens, with each distinct observation stored once
    /// (review A3) and keyed by [`Observation::digest`]. A realisation names the entry with which
    /// it was recorded.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub observations: BTreeMap<String, Observation>,
}

/// The identity of one object: the IDs of its material and the object type for which they were
/// computed. The identity is the same on every token.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockObject {
    /// The label with which the object's commitment schemes were computed. It is required when
    /// `ids` holds a commitment scheme. Verification uses this label and never the default label
    /// in the code.
    #[serde(default, rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The object type for which the IDs were computed. It is required when `ids` is not empty.
    /// When `keys.toml` declares a different type, the run refuses it with a type error instead
    /// of reporting a hash mismatch.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub object_type: Option<ObjectCfg>,
    /// The CA-IDs of the material, as a map from the scheme name to the SRI hash.
    #[serde(default)]
    pub ids: BTreeMap<String, String>,
    /// The other objects with the same public key (the same `rfc7093m4` ID), such as a key and its
    /// certificate, or a private key object and a public key object. cakeys records the pairs,
    /// each object of a pair lists the other one, and the load checks both.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pairs: BTreeSet<String>,
    /// The public key of a transport key (docs/CAMIGRATE.md D3): the base64 encoding of the
    /// canonical SPKI whose hash is `ids.rfc7093m4`. It is recorded when a token's `transportWith`
    /// spec is realised, so that a source token can export to this key with only the lock. The
    /// load checks the public key against that ID.
    #[serde(default, rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl LockObject {
    fn has_commitments(&self) -> bool {
        self.ids.keys().any(|s| Scheme::from_name(s).is_some_and(Scheme::is_commitment))
    }
}

/// The version of the lock format. The format is not published yet, so its schema changes
/// without a new version number.
pub const LOCK_VERSION: u32 = 1;

impl Lock {
    /// Refuses every version other than [`LOCK_VERSION`] (the version is required), then checks
    /// every lock invariant: the IDs and the label of each object, each realisation against its
    /// object, the observations, one object per material, and pairs that list each other. The
    /// load runs this check, and [`save_lock`](super::save_lock) runs it before it writes, so no
    /// verb can save a lock that would fail to load.
    pub(super) fn check(&self, path: &Path) -> Result<()> {
        if self.version != LOCK_VERSION {
            return Err(KmError::Validation(
                format!(
                    "{}: lock version {} is not supported (this cakeys reads {LOCK_VERSION})",
                    path.display(),
                    self.version
                )
                .into(),
            ));
        }
        let invalid = |msg: String| KmError::Validation(format!("{}: {msg}", path.display()).into());
        self.check_objects().map_err(invalid)?;
        self.check_realisations().map_err(invalid)?;
        self.check_observations().map_err(invalid)?;
        self.check_one_object_per_material().map_err(invalid)?;
        self.check_pairs().map_err(invalid)
    }

    /// Checks each object: its IDs must be SRI digests under the scheme names that the lock uses
    /// (not an input alias or an attestation scheme), an object with IDs must have a type, an
    /// object with commitment IDs must have a printable label, and a recorded public key must
    /// hash to the object's `rfc7093m4` ID.
    fn check_objects(&self) -> std::result::Result<(), String> {
        for (name, o) in &self.objects {
            if o.has_commitments() && o.commitment_label.is_none() {
                return Err(format!("object '{name}' has commitment IDs but no commitmentLabel"));
            }
            if let Some((alias, scheme)) = Scheme::ALIASES.iter().find(|(a, _)| o.ids.contains_key(*a)) {
                return Err(format!(
                    "object '{name}' records '{alias}', which is an input alias; the lock uses '{scheme}'"
                ));
            }
            if !o.ids.is_empty() && o.object_type.is_none() {
                return Err(format!("object '{name}' has IDs but no type"));
            }
            if let Some((s, v)) = o.ids.iter().find(|(_, v)| !crate::id::is_sri(v)) {
                return Err(format!("object '{name}': {s} = \"{v}\" is not a sha256 SRI digest"));
            }
            // An attestation ID belongs to one device (§3.7). The same material attested on two
            // TPMs has two attestation IDs, so each ID is stored on its realisation and never in
            // the object's `ids`, which every token shares.
            if let Some(s) = o.ids.keys().find(|s| Scheme::from_name(s).is_some_and(Scheme::is_attestation)) {
                return Err(format!(
                    "object '{name}' records the attestation scheme {s}: an attestation ID is per device \
                     and belongs to the realisation that computed it (realisations.<spec>.<token>.attestation)"
                ));
            }
            if let Some(l) = o
                .commitment_label
                .as_ref()
                .filter(|l| l.is_empty() || !l.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
            {
                return Err(format!("object '{name}': commitmentLabel {l:?} must be non-empty printable ASCII"));
            }
            if let Some(k) = &o.public_key {
                use base64::Engine as _;
                let der = base64::engine::general_purpose::STANDARD
                    .decode(k)
                    .map_err(|e| format!("object '{name}': publicKey is not base64: {e}"))?;
                match o.ids.get(Scheme::Rfc7093m4.name()) {
                    Some(id) if *id == crate::id::sri(&der) => {}
                    Some(id) => {
                        return Err(format!(
                            "object '{name}': publicKey hashes to {}, not the {id} its rfc7093m4 pins",
                            crate::id::sri(&der)
                        ));
                    }
                    None => return Err(format!("object '{name}': publicKey without an rfc7093m4 ID to check it by")),
                }
            }
        }
        Ok(())
    }

    /// Checks each realisation: it must name an object of the lock and only schemes among that
    /// object's IDs. It must have a binding if and only if the object is a private key. Its
    /// attestation evidence, if any, must be of a known kind and must not be the only scheme.
    fn check_realisations(&self) -> std::result::Result<(), String> {
        for (spec, by_token) in &self.realisations {
            for (token, r) in by_token {
                let what = format!("realisation of '{spec}' on '{token}'");
                if !crate::id::is_sri(&r.spec_digest) {
                    return Err(format!("{what}: specDigest \"{}\" is not a sha256 SRI digest", r.spec_digest));
                }
                let Some(o) = self.objects.get(&r.object) else {
                    return Err(format!("{what}: object '{}' is not in the lock", r.object));
                };
                if let Some(s) = r.schemes.iter().find(|s| !o.ids.contains_key(*s)) {
                    return Err(format!("{what}: scheme {s} is not among the IDs of '{}'", r.object));
                }
                let private = o.object_type.as_ref().is_some_and(|t| t.class == ObjectClass::PrivateKey);
                if private != r.binding.is_some() {
                    return Err(format!(
                        "{what}: binding is {} for private keys and only for them",
                        if private { "required" } else { "allowed" }
                    ));
                }
                if let Some(o) = r.provenance.as_ref().and_then(|p| p.origin.as_ref())
                    && crate::migrate::Method::from_name(&o.method).is_none()
                {
                    return Err(format!("{what}: provenance origin method '{}' is unknown", o.method));
                }
                // Attestation evidence (§3.7) must have a known kind and SRI digests, and it must
                // not be the only scheme. The realisation must also have matched a portable
                // scheme, because only a portable scheme links the same material on another token.
                let Some(a) = &r.attestation else { continue };
                if Scheme::from_attestation_kind(&a.kind).is_none() {
                    return Err(format!(
                        "{what}: unknown attestation kind '{}' (known: {:?})",
                        a.kind,
                        Scheme::ALL.into_iter().filter_map(Scheme::attestation_kind).collect::<Vec<_>>()
                    ));
                }
                if let Some((field, v)) =
                    [("root", &a.root), ("id", &a.id)].into_iter().find(|(_, v)| !crate::id::is_sri(v))
                {
                    return Err(format!("{what}: attestation {field} \"{v}\" is not a sha256 SRI digest"));
                }
                if r.schemes.is_empty() {
                    return Err(format!(
                        "{what} is locked only by its attestation: an attestation is provenance for one \
                         device and cannot verify the same material on another token; it needs a portable \
                         scheme (rfc7093m4, or a commitment for secret keys) beside it"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks that each observation is keyed by an SRI digest and that each realisation names an
    /// observation that the lock has. The key is not computed again here, because an entry may
    /// hold fields of a newer cakeys (`extra`) that this version cannot hash.
    fn check_observations(&self) -> std::result::Result<(), String> {
        if let Some(k) = self.observations.keys().find(|k| !crate::id::is_sri(k)) {
            return Err(format!("observation key \"{k}\" is not a sha256 SRI digest"));
        }
        if let Some(h) =
            self.observations.values().filter_map(|o| o.module.as_ref()?.hash.as_ref()).find(|h| !crate::id::is_sri(h))
        {
            return Err(format!("observation module hash \"{h}\" is not a sha256 SRI digest"));
        }
        for (spec, by_token) in &self.realisations {
            for (token, r) in by_token {
                if let Some(k) = r.observation.as_ref().filter(|k| !self.observations.contains_key(*k)) {
                    return Err(format!(
                        "realisation of '{spec}' on '{token}': observation \"{k}\" is not in the lock"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns the observation that the realisations on `token` name (review A3). When they all
    /// name the same observation, the lock treats it as the observation of that token.
    #[must_use]
    pub fn token_observation(&self, token: &str) -> TokenObservation<'_> {
        let mut named: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (spec, by_token) in &self.realisations {
            if let Some(k) = by_token.get(token).and_then(|r| r.observation.as_deref()) {
                named.entry(k).or_default().push(spec);
            }
        }
        match named.len() {
            0 => TokenObservation::None,
            1 => named
                .keys()
                .next()
                .and_then(|k| self.observations.get(*k))
                .map_or(TokenObservation::None, TokenObservation::One),
            _ => TokenObservation::Several(
                named.into_values().map(|specs| specs.into_iter().map(str::to_owned).collect()).collect(),
            ),
        }
    }

    /// Returns the observation keys that no realisation names. Only the realisations that `keep`
    /// accepts (given the spec name and the token name) are counted.
    fn unreferenced_observations(&self, keep: &dyn Fn(&str, &str) -> bool) -> Vec<String> {
        let named: BTreeSet<&str> = self
            .realisations
            .iter()
            .flat_map(|(spec, by_token)| {
                by_token.iter().filter(|(t, _)| keep(spec, t)).filter_map(|(_, r)| r.observation.as_deref())
            })
            .collect();
        self.observations.keys().filter(|k| !named.contains(k.as_str())).cloned().collect()
    }

    /// Removes the observations that no realisation names. Returns whether it removed any.
    pub fn drop_unreferenced_observations(&mut self) -> bool {
        let gone = self.unreferenced_observations(&|_, _| true);
        for k in &gone {
            self.observations.remove(k);
        }
        !gone.is_empty()
    }

    /// Checks that the lock holds one object per material. Two objects of the same class with the
    /// same ID are the same material under two names. A certificate's `rfc7093m4` ID identifies
    /// the key that the certificate certifies, and several certificates may share that key, so
    /// that ID is not compared between certificates.
    fn check_one_object_per_material(&self) -> std::result::Result<(), String> {
        let mut seen: BTreeMap<(&str, &str, &str), &str> = BTreeMap::new();
        for (name, o) in &self.objects {
            let class = o.object_type.as_ref().map_or("", |t| t.class.name());
            for (s, v) in o
                .ids
                .iter()
                .filter(|(s, _)| !(class == ObjectClass::Certificate.name() && *s == Scheme::Rfc7093m4.name()))
            {
                if let Some(other) = seen.insert((s, class, v), name) {
                    return Err(format!(
                        "objects '{other}' and '{name}' are the same {class} material ({s} {v}); use one object"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks the pairs. A listed pair that is in this file must share the public key and must
    /// list this object in return. A listed pair that is not in this file may be in another lock
    /// fragment, because locks can be split and joined.
    fn check_pairs(&self) -> std::result::Result<(), String> {
        for (name, o) in &self.objects {
            for p in &o.pairs {
                if p == name {
                    return Err(format!("object '{name}' lists itself as a pair"));
                }
                let Some(other) = self.objects.get(p) else { continue };
                let shared = o
                    .ids
                    .get(Scheme::Rfc7093m4.name())
                    .is_some_and(|k| other.ids.get(Scheme::Rfc7093m4.name()) == Some(k));
                if !shared || !other.pairs.contains(name) {
                    return Err(format!(
                        "object '{name}' lists '{p}' as a pair, but they {}",
                        if shared { "do not list each other" } else { "do not share an rfc7093m4" }
                    ));
                }
            }
        }
        Ok(())
    }

    /// The realisation of `spec` on `token`, if the lock records one.
    #[must_use]
    pub fn realisation(&self, spec: &str, token: &str) -> Option<&LockRealisation> {
        self.realisations.get(spec)?.get(token)
    }

    /// Returns the objects in this file that share an `rfc7093m4` ID with `name` but are not
    /// listed as its pairs.
    #[must_use]
    pub fn unlisted_pairs(&self, name: &str) -> BTreeSet<String> {
        let listed = self.objects.get(name).map(|o| &o.pairs);
        self.computed_pairs()
            .remove(name)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| listed.is_none_or(|l| !l.contains(p)))
            .collect()
    }

    /// Returns, for every object, the other objects with the same public key (the same
    /// `rfc7093m4` ID).
    #[must_use]
    pub fn computed_pairs(&self) -> BTreeMap<String, BTreeSet<String>> {
        let key = |o: &LockObject| o.ids.get(Scheme::Rfc7093m4.name()).cloned();
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

/// One realisation of a spec on a token. The fields fall into three classes (docs/DESIGN.md
/// §4.2):
/// - **compared** (the top-level fields): verification fails when they differ from keys.toml or
///   from the token;
/// - **`observed`** and **`observation`**: recorded facts about the object and the token (the
///   `observation` is the key of an entry in the lock's `observations`). They never change the
///   result;
/// - **`provenance`**: the object's history (`origin`). It never changes the result either.
///
/// Removing `observed`, `observation`, `provenance` and the `observations` table from a lock
/// never changes the result of a run.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LockRealisation {
    /// The object that this spec realised. When keys.toml points the spec at another object or
    /// another locator, a person must review the change, and the run does not report it as a hash
    /// mismatch.
    pub object: String,
    /// The locator under which the run found the object (see `object`).
    pub(crate) locator: Locator,
    /// The SRI digest of the spec (the object type and the policy attributes) under which the
    /// realisation was recorded. A different digest means that the spec changed.
    pub(crate) spec_digest: String,
    /// The identity mode in which the realisation was established. A weaker mode in a later run
    /// is a downgrade (exit 14).
    pub(crate) mode: Mode,
    /// The identity schemes that this realisation computed and matched. A later run that computes
    /// fewer of them is a downgrade. The field also shows which realisation established which
    /// locked ID.
    pub schemes: BTreeSet<String>,
    /// True when the object was adopted through its public key object only (`publicOnly`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) public_only: bool,
    /// For a private key: how the private object is bound to the identity. It is `None` for every
    /// other class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// The attestation that this realisation pinned (§3.7 of docs/DESIGN.md), when its spec opted
    /// in: the attestation ID of this device and the *anchor* against which it was verified,
    /// which is the Yubico root (PIV) or the Attestation Key (TPM). It is stored here and not in
    /// `objects.<name>.ids`, because the same material attested on two devices has two IDs. The
    /// portable `schemes` link the two realisations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
    /// Every boolean attribute that the object exposes for its class (`CKA_SIGN = true`, ...), as
    /// read from the token, whether the spec declares it or not. A person must review any change.
    pub policy: BTreeMap<String, AttrValue>,
    /// The attributes that were fixed when the object was created. When one of them becomes
    /// weaker, the object was replaced.
    #[serde(default, skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    /// The key of the `observations` entry with which this realisation was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<String>,
    /// What the run saw of the object when it recorded the realisation. It is never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<Observed>,
    /// The object's history on this token. It is never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provenance: Option<Provenance>,
}

impl LockRealisation {
    /// Returns the value of a boolean attribute as the token reported it when this realisation
    /// was recorded, or `Why::Unrecorded` when the lock has no record of it.
    pub fn observed(&self, name: &str) -> Known<bool> {
        Known::or(
            match self.policy.get(name) {
                Some(AttrValue::Bool(b)) => Some(*b),
                _ => None,
            },
            Why::Unrecorded,
        )
    }
}

/// Attestation evidence that can be verified offline, pinned for each realisation (§3.7 of
/// docs/DESIGN.md). `kind` names the attestation (`yubico-piv` or `tpm-certify`, one for each
/// scheme; see `Scheme::attestation_kind`). `root` is the SRI digest of the trust anchor to which
/// the chain was verified: the SPKI of the pinned Yubico root for PIV (never the device's own
/// slot f9, which can be overwritten), or the SPKI of the Attestation Key for TPM. `id` is the
/// attestation commitment of this device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttestationRecord {
    /// The attestation kind (`yubico-piv`, `tpm-certify`).
    pub kind: String,
    /// The SRI digest of the trust anchor to which the attestation was verified.
    pub root: String,
    /// The attestation commitment of this device.
    pub id: String,
}

/// The key attributes that the token sets when the key is created. No later operation can set
/// them back to `true` (PKCS#11 3.2 §4.9-4.10), so a change from `true` to `false` means that the
/// object was replaced, for example by a new import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Immutables {
    /// `CKA_LOCAL`: the key was generated on the token.
    #[serde(rename = "CKA_LOCAL", default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    /// `CKA_NEVER_EXTRACTABLE`: the key has never been extractable.
    #[serde(rename = "CKA_NEVER_EXTRACTABLE", default, skip_serializing_if = "Option::is_none")]
    pub never_extractable: Option<bool>,
    /// `CKA_ALWAYS_SENSITIVE`: the key has always been sensitive.
    #[serde(rename = "CKA_ALWAYS_SENSITIVE", default, skip_serializing_if = "Option::is_none")]
    pub always_sensitive: Option<bool>,
    /// `CKA_KEY_GEN_MECHANISM`: the `CKM_...` mechanism that generated the key. It is `None` when
    /// the token reports none, as for an imported key.
    #[serde(rename = "CKA_KEY_GEN_MECHANISM", default, skip_serializing_if = "Option::is_none")]
    pub key_gen_mechanism: Option<String>,
}

impl Immutables {
    /// Returns true when nothing is recorded, as for a class without these attributes. The lock
    /// then leaves the field out.
    #[must_use]
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

    /// Returns the flags that were `true` when the lock recorded them and are not `true` now.
    #[must_use]
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

/// Formats the immutables as a TOML inline table, in the form that the lock writes.
impl std::fmt::Display for Immutables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {} }}", self.fields().join(", "))
    }
}

/// Returns the lock entries that `cfg` no longer names (finding D3). These are every
/// `[realisations.<spec>.<token>]` whose spec or token was removed from keys.toml, every
/// `[objects.<name>]` that keys.toml no longer defines, and every `[observations."<key>"]` that
/// no remaining realisation names. `gc --dry-run` prints them as table names, and `gc` removes
/// them.
///
/// An object that keys.toml still defines keeps its `ids`, however few specs use it. A
/// realisation of an object that keys.toml no longer defines (a renamed object, or a spec that
/// now points at another object) is removed with the object, so that the remaining lock loads.
/// With `remove`, the function removes exactly the returned entries.
pub fn gc(cfg: &Config, lock: &mut Lock, remove: bool) -> Vec<String> {
    let named = |spec: &str, token: &str| cfg.specs.get(spec).is_some_and(|s| s.tokens.contains_key(token));
    let kept: BTreeSet<(String, String)> = lock
        .realisations
        .iter()
        .flat_map(|(spec, tokens)| {
            tokens
                .iter()
                .filter(|(t, r)| named(spec, t) && cfg.objects.contains_key(&r.object))
                .map(move |(t, _)| (spec.clone(), t.clone()))
        })
        .collect();
    let keep = |spec: &str, token: &str| kept.contains(&(spec.to_owned(), token.to_owned()));
    let mut stale: Vec<String> = lock
        .realisations
        .iter()
        .flat_map(|(spec, tokens)| {
            tokens.keys().filter(|t| !keep(spec, t)).map(move |t| format!("realisations.{spec}.{t}"))
        })
        .collect();
    stale.extend(lock.objects.keys().filter(|o| !cfg.objects.contains_key(*o)).map(|o| format!("objects.{o}")));
    let observations = lock.unreferenced_observations(&keep);
    stale.extend(observations.iter().map(|k| format!("observations.\"{k}\"")));
    if remove {
        for (spec, tokens) in &mut lock.realisations {
            tokens.retain(|t, _| keep(spec, t));
        }
        lock.realisations.retain(|_, tokens| !tokens.is_empty());
        lock.objects.retain(|o, _| cfg.objects.contains_key(o));
        lock.observations.retain(|k, _| !observations.contains(k));
    }
    stale
}

/// The identity modes, with the strongest mode first (docs/DESIGN.md §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// The ID is a hash of the object's public material: public keys, certificates and data
    /// objects.
    Direct,
    /// The ID is a hash of a commitment that the token computes with the secret key (a MAC, a
    /// check value or a wrap). This mode is for secret keys whose usage attributes allow such a
    /// computation.
    Commitment,
    /// This mode is for an extractable secret key whose usage attributes allow no commitment. The
    /// run wraps the key under a session KEK and unwraps it as a session copy that allows every
    /// scheme of its type. It then computes the commitments with the copy and destroys both the
    /// copy and the KEK.
    WrapRebind,
}

/// How a private key object is bound to the public key whose hash is its identity (docs/DESIGN.md
/// §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Binding {
    /// The token signed a fresh challenge, and the host verified the signature with that public
    /// key.
    PopSign,
    /// `pop-sign` on a `CKA_ALWAYS_AUTHENTICATE` key: the same proof, with the
    /// `C_Login(CKU_CONTEXT_SPECIFIC)` that the key requires before each signature. The run
    /// derives this binding from the observed attribute and records it in the lock. keys.toml
    /// never declares it.
    PopSignPin,
    /// The token derived the ECDH shared secret with an ephemeral host key, and both the token
    /// and the host computed a MAC of the challenge with that secret (for EC keys that can only
    /// derive).
    PopEcdh,
    /// The token decrypted a challenge from the host (RSA-OAEP) to the expected plaintext (for RSA
    /// keys that can only decrypt).
    PopDecrypt,
    /// The token unwrapped a secret from the host (RSA-OAEP) into a non-extractable session key,
    /// and both the token and the host computed a MAC of the challenge with it (for RSA keys that
    /// can only unwrap, which are the transport keys of docs/CAMIGRATE.md D3).
    PopUnwrap,
    /// No proof of possession: only the token's report ties the private key to the identity
    /// (with the opt-in `binding = "token-asserted"`, or with `publicOnly`).
    TokenAsserted,
}

impl Binding {
    /// Returns the strength of the binding, where 0 is the strongest. A realisation must never
    /// move to a higher rank. Every `pop-*` binding proves the same fact, which is possession of
    /// the named public key, with whichever capability the key has. `pop-sign-pin` proves it too.
    /// The PIN that it requires for each use is recorded by the observed `CKA_ALWAYS_AUTHENTICATE`
    /// attribute in the policy, not by a weaker rank.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Binding::PopSign | Binding::PopSignPin | Binding::PopEcdh | Binding::PopDecrypt | Binding::PopUnwrap => 0,
            Binding::TokenAsserted => 1,
        }
    }

    /// Returns the proof of possession of this binding, from the table of names that the
    /// capability profiles share (`cakeys_names::Proof`). Returns `None` for `token-asserted`,
    /// which proves nothing.
    #[must_use]
    pub fn proof(self) -> Option<cakeys_names::Proof> {
        use cakeys_names::Proof;
        match self {
            Binding::PopSign => Some(Proof::PopSign),
            Binding::PopSignPin => Some(Proof::PopSignPin),
            Binding::PopEcdh => Some(Proof::PopEcdh),
            Binding::PopDecrypt => Some(Proof::PopDecrypt),
            Binding::PopUnwrap => Some(Proof::PopUnwrap),
            Binding::TokenAsserted => None,
        }
    }

    /// Returns the name that keys.toml and the lock use, which is the name of its proof
    /// ([`Binding::proof`]).
    #[must_use]
    pub fn name(self) -> &'static str {
        self.proof().map_or("token-asserted", cakeys_names::Proof::name)
    }

    /// Returns the proof name that a capability row uses (`prove.<proof>.…`, docs/CAPROBE.md).
    /// That is the binding's own name, except that `pop-sign-pin` uses `pop-sign`. Returns `None`
    /// for `token-asserted`, which proves nothing.
    #[must_use]
    pub fn proof_name(self) -> Option<&'static str> {
        match self {
            Binding::PopSignPin => Some(Binding::PopSign.name()),
            proven => proven.proof().map(cakeys_names::Proof::name),
        }
    }
}

impl std::fmt::Display for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Mode {
    /// Returns the strength of the mode, where 0 is the strongest. A realisation must never move
    /// to a higher rank.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Mode::Direct => 0,
            Mode::Commitment => 1,
            Mode::WrapRebind => 2,
        }
    }

    /// Returns the name that the lock writes.
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

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::config::*;

    /// The synthetic fixture lock of the Nix library must remain a valid lock of the current
    /// schema.
    #[test]
    fn fixture_lock_parses() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../cli/tests/fixtures/keys.lock"));
        let lock = load_lock(path).unwrap();
        assert_eq!(lock.realisations["signing-soft"]["softhsm"].binding, Some(Binding::PopSign));
        // A recorded `CKA_ID` loads in lower case, as a `CKA_ID` in keys.toml does, so `0A` and
        // `0a` are the same locator and never a change to review (review D1). A `CKA_ID` that is
        // not hex cannot come from a lock that cakeys wrote, so the load refuses it.
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

    /// Observation keys from a newer cakeys load, and a rewrite of the lock keeps them (the TUF
    /// rule for re-serialization). An unknown key anywhere else, including in `provenance`, still
    /// makes the load refuse the lock.
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
        // The rename of the temporary file left no file in the directory except the lock.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // A compared table accepts no unknown key, and the object's history does not either.
        for (table, key) in [
            ("[realisations.signing-soft.softhsm]\n", "builder = \"ci-7\"\n"),
            ("[realisations.signing-soft.softhsm]\n", "provenance = { builder = \"ci-7\" }\n"),
        ] {
            std::fs::write(&path, text.replacen(table, &format!("{table}{key}"), 1)).unwrap();
            assert!(matches!(load_lock(&path), Err(KmError::Validation(_))), "{key}");
        }
    }

    /// A realisation must name an observation that the lock has (exit 17 otherwise), and an
    /// origin must name a known method. `gc` reports and removes exactly the observations that no
    /// remaining realisation names.
    #[test]
    fn observations_are_referenced_and_collected() {
        let path = Path::new("test.lock");
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let set = |lock: &mut Lock, f: &dyn Fn(&mut LockRealisation)| {
            f(lock.realisations.get_mut("s").unwrap().get_mut("t").unwrap());
        };
        let mut lock = attestable_lock();
        set(&mut lock, &|r| r.observation = Some(sri.into()));
        let err = lock.check(path).unwrap_err();
        assert!(err.to_string().contains("is not in the lock"), "{err}");
        lock.observations.insert(sri.into(), Observation::default());
        lock.observations.insert("sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=".into(), Observation::default());
        lock.check(path).unwrap();
        // The module hash of every observation is checked, not only the first one's (review
        // config.rs F2). The test puts a valid hash first and a malformed hash after it.
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
        let err = hashed.check(path).unwrap_err();
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
        assert!(bad.check(path).unwrap_err().to_string().contains("origin method"));

        let cfg: Config = toml::from_str(
            "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\ntokens.t = { locator = { CKA_LABEL = \"k\" } }\n",
        )
        .unwrap();
        let unnamed = "observations.\"sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=\"";
        assert_eq!(gc(&cfg, &mut lock.clone(), false), [unnamed]);
        // When the spec is removed, `gc` removes its realisation and the observation that only
        // that realisation named.
        let cfg = Config { specs: BTreeMap::new(), ..cfg };
        let stale = gc(&cfg, &mut lock, true);
        assert_eq!(stale.len(), 3, "{stale:?}");
        assert!(lock.realisations.is_empty() && lock.observations.is_empty());
    }

    /// `gc` leaves a lock that loads. When an object was renamed in keys.toml before `lock` ran,
    /// `gc` removes the realisation that still names the old object. Earlier, that realisation
    /// stayed and named an object that `gc` had removed, so every later run refused the lock,
    /// including `lock` and `gc`. Also, a lock that would not load is never written: `save_lock`
    /// refuses it and keeps the old file.
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
        lock.check(path).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keys.lock");
        let mut broken = attestable_lock();
        broken.objects.clear();
        // When a run saves, after a token write, a lock that would not load, the save fails with
        // exit 21 and names the load rule that the lock breaks (review 2026-11-23 A-17).
        let e = save_lock(&file, &broken).unwrap_err();
        assert!(e.exit_code() == 21 && e.to_string().contains("is not in the lock"), "{e}");
        assert!(!file.exists(), "an invalid lock was written");
        save_lock(&file, &attestable_lock()).unwrap();
        load_lock(&file).unwrap();
    }

    /// The downgrade check compares ranks, so an inverted order would disable it without any
    /// error. The `pop-*` bindings share rank 0, because each one proves possession of the same
    /// key.
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

    /// Every proof in the names table is a binding that keys.toml and the lock read under the
    /// proof's name. Both the serde spelling, which the file format fixes, and [`Binding::name`]
    /// use that name. So a binding, its `prove.*` row and the profiles' `Proof` have the same
    /// name.
    #[test]
    fn every_proof_is_a_binding_by_its_name() {
        for p in cakeys_names::Proof::ALL {
            let b: Binding = serde_json::from_value(serde_json::json!(p.name())).unwrap();
            assert_eq!((b.proof(), b.name()), (Some(p), p.name()), "{p:?}");
            assert_eq!(serde_json::to_value(b).unwrap(), serde_json::json!(b.name()), "{p:?}");
        }
        assert_eq!(Binding::TokenAsserted.proof(), None);
        assert_eq!(serde_json::to_value(Binding::TokenAsserted).unwrap(), "token-asserted");
    }

    /// Returns a minimal valid lock with one object and one realisation, for the tests of the
    /// lock invariants. The caller changes the lock and expects `Lock::check` to accept or
    /// refuse it.
    pub(crate) fn attestable_lock() -> Lock {
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

    /// An attestation ID belongs to one device and is never the only scheme (§3.7). It is stored
    /// on the realisation that computed it, and never in the object's `ids`, which every token
    /// shares and where the same material attested on a second TPM would need a second value.
    /// That realisation must also hold a portable scheme.
    #[test]
    fn attestation_is_per_realisation_and_never_alone() {
        let path = Path::new("test.lock");
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let record = |kind: &str| AttestationRecord { kind: kind.into(), root: sri.into(), id: sri.into() };
        let real = |lock: &mut Lock| lock.realisations.get_mut("s").unwrap().get_mut("t").unwrap().clone();
        let set = |lock: &mut Lock, r: LockRealisation| {
            lock.realisations.get_mut("s").unwrap().insert("t".into(), r);
        };

        // An attestation ID in the object's `ids` is refused, wherever it came from.
        let mut lock = attestable_lock();
        lock.objects.get_mut("k").unwrap().ids.insert("tpm-certify".to_owned(), sri.to_owned());
        let err = lock.check(path).unwrap_err();
        assert!(err.to_string().contains("belongs to the realisation"), "{err}");

        // An attestation on the realisation, next to a portable scheme, loads.
        let mut lock = attestable_lock();
        let mut r = real(&mut lock);
        r.attestation = Some(record("tpm-certify"));
        set(&mut lock, r.clone());
        lock.check(path).unwrap();

        // An attestation without a portable scheme (the realisation's portable schemes were
        // removed) is refused.
        let mut alone = lock.clone();
        let mut r2 = r.clone();
        r2.schemes.clear();
        set(&mut alone, r2);
        let err = alone.check(path).unwrap_err();
        assert!(err.to_string().contains("locked only by its attestation"), "{err}");

        // An unknown kind, or an `id` that is not an SRI digest, is refused.
        let mut bad = lock.clone();
        let mut r3 = r.clone();
        r3.attestation = Some(record("vendor-x"));
        set(&mut bad, r3);
        assert!(bad.check(path).unwrap_err().to_string().contains("unknown attestation kind"));
        let mut bad = lock;
        r.attestation.as_mut().unwrap().id = "nope".into();
        set(&mut bad, r);
        assert!(bad.check(path).unwrap_err().to_string().contains("attestation id"));
    }
}
