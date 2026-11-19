//! `keys.lock`: what was realised where, its invariants, and `gc`.

use super::{
    AttrValue, Binding, Config, Locator, Mode, ObjectCfg, Observation, Observed, Provenance, TokenObservation,
};
use crate::error::{KmError, Result};
use crate::id::Scheme;
use crate::types::ObjectClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A parsed `keys.lock` (docs/LOCK.md): each object's IDs and each spec's realisations, as
/// cakeys recorded them.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    /// The lock format version: a lock of any other than [`LOCK_VERSION`] is refused on load.
    pub version: u32,
    /// Each object's identity, by object name.
    #[serde(default)]
    pub objects: BTreeMap<String, LockObject>,
    /// spec name -> token name -> realisation
    #[serde(default)]
    pub realisations: BTreeMap<String, BTreeMap<String, LockRealisation>>,
    /// What realisations saw of their token, each distinct observation once (review A3), keyed
    /// by [`Observation::digest`]. A realisation names the entry it was recorded with.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub observations: BTreeMap<String, Observation>,
}

/// One object's identity: the IDs of its material and the type they were computed for, the
/// same on every token.
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
    /// A transport key's public key (docs/CAMIGRATE.md D3), base64 of the canonical SPKI whose hash is
    /// `ids.rfc7093m4`: recorded when a token's `transportWith` spec is realised, so a source
    /// exports to it from the lock alone. Checked against that ID on load.
    #[serde(default, rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl LockObject {
    fn has_commitments(&self) -> bool {
        self.ids.keys().any(|s| Scheme::from_name(s).is_some_and(Scheme::is_commitment))
    }
}

/// The lock format version. Unpublished, so its schema changes in place.
pub const LOCK_VERSION: u32 = 1;

impl Lock {
    /// Refuse other versions (the version is required), then every lock invariant: each object's
    /// IDs and label, each realisation against its object, one object per material, and pairs
    /// that list each other.
    pub(super) fn validate(self, path: &Path) -> Result<Lock> {
        self.check(path)?;
        Ok(self)
    }

    /// The load rules of [`Self::validate`], on a lock in memory: what [`save_lock`](super::save_lock) asks before
    /// it writes, so no verb can save a lock that would not load again.
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

    /// Each object's IDs are SRI digests under lock scheme names, need a type, and — for
    /// commitments — a printable label.
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
            // Attestation IDs are per device (§3.7): the same material attested on two TPMs has
            // two IDs, so they live on each realisation, never in the object's shared `ids`.
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

    /// Each realisation names an object of the lock and schemes among its IDs, a binding exactly
    /// when the object is a private key, and attestation evidence of a known kind that never
    /// stands alone.
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
                // Attestation evidence (§3.7): a known kind, SRI digests, and never alone — the
                // realisation must also have matched a portable scheme, the only thing that links
                // the same material on another token.
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

    /// Each observation is keyed by an SRI digest, and each realisation names one the lock has.
    /// The key is not recomputed here: an entry may hold keys of a newer cakeys (`extra`).
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

    /// The observation the realisations on `token` name (review A3): the token's as far as the
    /// lock knows, when they all agree.
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

    /// Observation keys no realisation names, or none of those `keep` accepts.
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

    /// Drop the observations no realisation names; whether any was dropped.
    pub fn drop_unreferenced_observations(&mut self) -> bool {
        let gone = self.unreferenced_observations(&|_, _| true);
        for k in &gone {
            self.observations.remove(k);
        }
        !gone.is_empty()
    }

    /// One object per material: two objects of one class with the same ID are the same thing
    /// under two names. A certificate's rfc7093m4 names its subject key, which several
    /// certificates may share.
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

    /// A listed partner that is in this file must share the public key and list back; one that is
    /// not may live in another lock fragment (locks can be split and joined).
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

    /// Objects in this file that share an rfc7093m4 with `name` but are not listed as its pairs.
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

    /// For every object, the other objects with the same public key (`rfc7093m4`).
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

/// One realisation of a spec on a token. Fields fall in three classes (docs/DESIGN.md §4.2):
/// - **compared** (top level): verification fails when they differ from keys.toml or the token;
/// - **`observed`** and **`observation`**: recorded facts about the object and the token (the
///   latter an entry of the lock's `observations`) that never change a verdict;
/// - **`provenance`**: the object's history (`origin`); never a verdict either.
///
/// Stripping `observed`, `observation`, `provenance` and the `observations` table from a lock
/// never changes a verdict.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LockRealisation {
    /// The object this spec realised and the locator it was found under: a spec pointed at
    /// another object or locator in keys.toml is a change to review, not a hash mismatch.
    pub object: String,
    /// The locator the object was found under (see `object`).
    pub(crate) locator: Locator,
    /// SRI digest of the spec (object type and policy attributes) it was recorded under: another
    /// digest is a spec change.
    pub(crate) spec_digest: String,
    /// The identity mode it was established in: a weaker one later is a downgrade (14).
    pub(crate) mode: Mode,
    /// The identity schemes this realisation computed and matched: computing fewer later is a
    /// downgrade. Also shows which realisation established which locked ID.
    pub schemes: BTreeSet<String>,
    /// Adopted through its public key object only (`publicOnly`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) public_only: bool,
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
    /// The key of the `observations` entry this realisation was recorded with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<String>,
    /// What was seen of the object when it was recorded; never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<Observed>,
    /// The object's history on this token; never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provenance: Option<Provenance>,
}

/// Offline-verifiable attestation evidence pinned per realisation (§3.7 of docs/DESIGN.md).
/// `kind` names the attestation (`yubico-piv`, `tpm-certify` — one per scheme, see
/// `id::ATTESTATION_KINDS`), `root` is the SRI digest of the trust anchor the chain was verified
/// to: the pinned Yubico root's SPKI for PIV (never the device's own overwritable slot f9), or
/// the Attestation Key's SPKI for TPM. `id` is the attestation commitment of this device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttestationRecord {
    /// The attestation kind (`yubico-piv`, `tpm-certify`).
    pub kind: String,
    /// SRI digest of the trust anchor the attestation was verified to.
    pub root: String,
    /// This device's attestation commitment.
    pub id: String,
}

/// Key attributes the token sets when the key is made, which no later operation can restore
/// (PKCS#11 3.2 §4.9-4.10): `true` → `false` means the object was replaced, e.g. re-imported.
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
    /// `CKM_...`, absent when the token reports none (an imported key).
    #[serde(rename = "CKA_KEY_GEN_MECHANISM", default, skip_serializing_if = "Option::is_none")]
    pub key_gen_mechanism: Option<String>,
}

impl Immutables {
    /// Nothing recorded (a class without these attributes): left out of the lock.
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

    /// Flags that were `true` when recorded and are not now.
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

/// Inline-table form, as the lock writes it.
impl std::fmt::Display for Immutables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {} }}", self.fields().join(", "))
    }
}

/// Lock entries `cfg` no longer names (finding D3): every `[realisations.<spec>.<token>]` whose
/// spec or token is gone from keys.toml, and every `[objects.<name>]` absent from it — printed by
/// `gc` as table names, removed with `--apply`. Live objects keep their `ids` however few specs
/// use them; only entries whose whole subject is gone are collected, and every
/// `[observations."<key>"]` no remaining realisation names. A realisation of an object keys.toml
/// no longer defines goes with it (a renamed object, a spec pointed at another one), so what is
/// left is a lock that loads. With `remove`, exactly the returned entries are dropped.
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
