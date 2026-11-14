//! The lock rules: compare what a token holds (a [`Resolved`]) with what the lock records, and
//! record what the lock lacks. Pure — no token access — so every rule is unit-testable. What a
//! run has to say besides its verdict (drift it tolerates, provenance changes, unchecked
//! schemes) goes into [`Notes`], which the caller prints whether or not the run succeeded.

use crate::config::{
    AttestationRecord, AttrValue, Binding, Immutables, Lock, LockRealisation, Mode, Observed, Provenance, Session,
};
use crate::id::{self, Scheme};
use crate::plan::Target;
use crate::types::ObjectClass as Class;
use crate::{KmError, Result};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct Resolved {
    pub object: String,
    pub spec: String,
    pub token: String,
    pub uri: String,
    pub mode: Mode,
    #[serde(rename = "publicOnly")]
    pub public_only: bool,
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
    pub ids: BTreeMap<String, String>,
    /// Private keys: how the private object was bound to `ids` (proven when `pop-sign`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// What the check establishes against a token that may lie: a fresh proof, a replayable
    /// fingerprint, or public bytes (`plan::assurance`; derived, never in the lock).
    pub assurance: crate::plan::Assurance,
    /// The observed policy vector and immutables of the object found (§4.2 of docs/DESIGN.md).
    pub policy: BTreeMap<String, AttrValue>,
    #[serde(skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    /// Label the commitment schemes in `ids` were computed with (none for public-material IDs).
    #[serde(rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The attestation this realisation computed (§3.7), when its spec opted in: `kind` names
    /// the evidence, `root` the anchor it verified to, `id` the per-device attestation ID. Never
    /// in `ids`, which holds only the portable schemes shared across tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
}

/// What a run has to say besides its verdict, in order. The caller prints them on success and
/// on error alike (before the error), so a warning is never lost to a failure after it.
#[derive(Debug, Default)]
pub struct Notes(Vec<String>);

impl Notes {
    /// A line as is (`created …`, `updated …`).
    pub fn say(&mut self, line: impl Into<String>) {
        self.0.push(line.into());
    }

    pub fn note(&mut self, msg: impl std::fmt::Display) {
        self.0.push(format!("note: {msg}"));
    }

    pub fn warn(&mut self, msg: impl std::fmt::Display) {
        self.0.push(format!("warning: {msg}"));
    }

    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.0
    }
}

/// Whether a run records what the lock lacks (`realise`, `delete` by default) or only compares
/// (`--no-update-lock`, and always for `verify` and `check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockWrite {
    Compare,
    Record,
}

/// What this run observed of the token and what produced it: recorded on `realise`, compared
/// (warnings only) with what the lock recorded.
pub struct Facts {
    pub observed: Observed,
    pub provenance: Provenance,
}

/// The label to compute `t`'s commitments with: the one the lock records for the object, else the
/// default for objects the lock does not know yet.
#[must_use]
pub fn commitment_label(t: &Target, lock: &Lock) -> String {
    lock.objects
        .get(t.object_name)
        .and_then(|o| o.commitment_label.clone())
        .unwrap_or_else(|| id::DEFAULT_COMMITMENT_LABEL.to_owned())
}

/// Compare `r` with the lock, then, with `LockWrite::Record`, record what the lock lacks (only
/// ever filling gaps). Whether the lock changed.
///
/// # Errors
///
/// Whatever `compare` rejects: `HashMismatch` when the token's material hashes to another ID
/// than the lock pins, `PreconditionFailed` for a realisation that moved (type, downgrade,
/// replaced object, attestation anchor) or a first use under `LockWrite::Compare`.
pub fn reconcile(
    t: &Target,
    r: &Resolved,
    lock: &mut Lock,
    facts: &Facts,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<bool> {
    compare(t, r, lock, facts, write, notes)?;
    match write {
        LockWrite::Compare => Ok(false),
        LockWrite::Record => record(t, r, lock, facts, notes),
    }
}

/// Every rule a realisation must pass against the lock, in the order that decides the exit code.
/// With `LockWrite::Record`, a changed spec or policy and a first use are what the write is for,
/// so they pass here (`record` says what it accepted); type changes, downgrades, a replaced
/// object, an attestation anchor change and a hash mismatch fail either way.
///
/// # Errors
///
/// `HashMismatch` (10) when the token's material hashes to another ID than the lock pins;
/// `PreconditionFailed` (14) for a type change, a downgrade, a replaced object, an attestation
/// anchor change, or a first use compared without the write.
pub fn compare(
    t: &Target,
    r: &Resolved,
    lock: &Lock,
    facts: &Facts,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<()> {
    let update = write == LockWrite::Record;
    // The lock pins the type its IDs were computed for: a different type is different material,
    // so say so instead of reporting a hash mismatch (also when updating).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref())
        && locked != t.object
    {
        return Err(KmError::PreconditionFailed(format!(
            "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
             different material needs a new object name",
            t.object_name, locked, t.object
        )));
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        if !update {
            spec_unchanged(t, r, prev)?;
        }
        no_downgrade(t, r, prev, update, notes)?;
        if !update {
            object_unchanged(t, r, prev, notes)?;
        }
        warn_provenance(t, prev, facts, notes);
    }
    let unlisted = lock.unlisted_pairs(t.object_name);
    if !update && !unlisted.is_empty() {
        notes.note(format_args!(
            "{unlisted:?} share the public key of '{}' but are not listed as its pairs; `realise` records them",
            t.object_name
        ));
    }
    compare_ids(t, r, lock, update, notes)
}

/// Like a lockfile out of date: keys.toml changed what this realisation is (another object,
/// locator, publicOnly or policy), so the lock must be re-recorded after review.
fn spec_unchanged(t: &Target, r: &Resolved, prev: &LockRealisation) -> Result<()> {
    let diff = spec_diff(t, r, prev);
    if diff.is_empty() {
        return Ok(());
    }
    Err(KmError::PreconditionFailed(format!(
        "spec '{}' changed in keys.toml since it was realised on '{}' ({}); review the change, then `realise`",
        t.spec_name,
        t.token_name,
        diff.join(", ")
    )))
}

/// What keys.toml now says of this realisation that the lock does not.
fn spec_diff(t: &Target, r: &Resolved, prev: &LockRealisation) -> Vec<String> {
    let mut diff = Vec::new();
    if prev.object != t.object_name {
        diff.push(format!("object '{}' -> '{}'", prev.object, t.object_name));
    }
    if prev.locator != t.on_token.locator {
        diff.push(format!("locator {} -> {}", prev.locator, t.on_token.locator));
    }
    if prev.public_only != r.public_only {
        diff.push(format!("publicOnly {} -> {}", prev.public_only, r.public_only));
    }
    if prev.spec_digest != r.spec_digest {
        diff.push(format!("spec digest {} -> {}", prev.spec_digest, r.spec_digest));
    }
    diff
}

/// What the realisation proved when it was locked, it must still prove — also when `realise`
/// writes the lock: its mode, binding, attestation and schemes, and the immutables fixed when the
/// object was made.
fn no_downgrade(t: &Target, r: &Resolved, prev: &LockRealisation, update: bool, notes: &mut Notes) -> Result<()> {
    if r.mode > prev.mode {
        return Err(KmError::PreconditionFailed(format!(
            "identity downgrade for {}: locked mode '{}', now only '{}'",
            t, prev.mode, r.mode
        )));
    }
    if let (Some(was), Some(now)) = (prev.binding, r.binding)
        && now.rank() > was.rank()
    {
        return Err(KmError::PreconditionFailed(format!(
            "binding downgrade for {t}: locked binding '{was}', now only '{now}'"
        )));
    }
    // The attestation is compared, even when realise writes the lock (§3.7). A different anchor means
    // a different device (or a re-provisioned TPM) signed the provenance; a different ID
    // under the same anchor means the attested object changed (re-imported, other
    // attributes or policy). Both are changes to review, never to re-record — and a lost
    // attestation is a scheme downgrade.
    match (&prev.attestation, &r.attestation) {
        (Some(was), Some(now)) if was.kind != now.kind || was.root != now.root => {
            return Err(KmError::PreconditionFailed(format!(
                "attestation anchor for {} changed since it was realised ({} root {}, now {} root {}); \
                 the material needs a new object name",
                t, was.kind, was.root, now.kind, now.root
            )));
        }
        (Some(was), Some(now)) if was.id != now.id => {
            return Err(KmError::HashMismatch {
                what: format!("{} ({} attestation)", t, was.kind),
                expected: was.id.clone(),
                got: now.id.clone(),
            });
        }
        (Some(was), None) => {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: it was realised with a {} attestation, which it no longer computes",
                t, was.kind
            )));
        }
        (None, Some(now)) if !update => {
            notes.note(format_args!(
                "{} also has a {} attestation the lock does not record; `realise` adds it",
                t, now.kind
            ));
        }
        _ => {}
    }
    let lost: Vec<&String> = prev.schemes.iter().filter(|s| !r.ids.contains_key(*s)).collect();
    if !lost.is_empty() {
        return Err(KmError::PreconditionFailed(format!(
            "identity downgrade for {t}: it was realised with {lost:?}, which it no longer computes"
        )));
    }
    // Fixed at creation: weaker now means the object was replaced (also when updating).
    let weakened = r.immutables.weakened_since(&prev.immutables);
    if !weakened.is_empty() {
        return Err(KmError::PreconditionFailed(format!(
            "{} was replaced since it was realised: {} no longer true; a new object needs a new name",
            t,
            weakened.join(", ")
        )));
    }
    Ok(())
}

/// The token's object changed (policy set since, or another object with the same material):
/// review, like a changed spec.
fn object_unchanged(t: &Target, r: &Resolved, prev: &LockRealisation, notes: &mut Notes) -> Result<()> {
    let diff = object_diff(r, prev);
    if !diff.is_empty() {
        return Err(KmError::PreconditionFailed(format!(
            "{} changed on the token since it was realised ({}); review, then `realise`",
            t,
            diff.join(", ")
        )));
    }
    let new: Vec<&String> = r.policy.keys().filter(|n| !prev.policy.contains_key(*n)).collect();
    if !new.is_empty() {
        notes.note(format_args!("{t} also reports {new:?}, which the lock does not record; `realise` adds them"));
    }
    Ok(())
}

/// What the token's object now shows that the lock recorded otherwise.
fn object_diff(r: &Resolved, prev: &LockRealisation) -> Vec<String> {
    let mut diff: Vec<String> = prev
        .policy
        .iter()
        .filter(|(n, was)| r.policy.get(*n) != Some(was))
        .map(|(n, was)| {
            format!("{n} {was} -> {}", r.policy.get(n).map_or("unreadable".into(), std::string::ToString::to_string))
        })
        .collect();
    if prev.immutables != r.immutables {
        diff.push(format!("immutables {} -> {}", prev.immutables, r.immutables));
    }
    diff
}

/// The IDs against the object's locked ones: a mismatch is 10, and so is a first use when only
/// comparing; then the realisation itself must be locked (14). Notes what is not checked.
fn compare_ids(t: &Target, r: &Resolved, lock: &Lock, update: bool, notes: &mut Notes) -> Result<()> {
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    // A deprecated computation still verifies — its identities are pinned — but the lock should
    // move to the replacement (docs/DESIGN.md §3.1); a lock write never adds a new one.
    for scheme in
        locked.iter().flat_map(|ids| ids.keys()).filter(|s| Scheme::from_name(s).is_some_and(Scheme::is_deprecated))
    {
        notes.warn(format_args!(
            "the {scheme} identity of '{}' uses a deprecated computation; migrate to its replacement (docs/DESIGN.md §3.1)",
            t.object_name
        ));
    }
    // Material is only linked through a shared scheme: never attach IDs to an object when none of
    // them can be compared with what is already locked (e.g. a CMAC-only and a KW-only spec).
    if let Some(ids) = locked.filter(|ids| !ids.is_empty())
        && !r.ids.keys().any(|s| ids.contains_key(s))
    {
        return Err(KmError::PreconditionFailed(format!(
            "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
             material; realise a spec that computes both first",
            t,
            r.ids.keys().collect::<Vec<_>>(),
            t.object_name,
            ids.keys().collect::<Vec<_>>()
        )));
    }
    let mut matched = false;
    let mut unlocked = Vec::new();
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => matched = true,
            Some(want) => {
                return Err(KmError::HashMismatch { what: t.to_string(), expected: want.clone(), got: got.clone() });
            }
            // Recorded by `record` (a deprecated one is not).
            None if update => {}
            None => unlocked.push((scheme, got)),
        }
    }
    // A scheme not yet in the lock (e.g. one a newer cakeys computes) is fine once another
    // scheme proved the identity; with nothing to compare it is first use and fails like a FOD.
    if let Some((_, got)) = unlocked.first().filter(|_| !matched) {
        return Err(KmError::HashMismatch { what: t.to_string(), expected: "<none>".into(), got: (*got).clone() });
    }
    // The material matches, but the lock does not say this spec is realised on this token: the
    // lock describes where objects live, not only what they are.
    if !update && lock.realisation(t.spec_name, t.token_name).is_none() {
        return Err(KmError::PreconditionFailed(format!(
            "{} matches the locked identity, but the lock records no realisation of spec '{}' on \
             token '{}'; review, then `realise`",
            t, t.spec_name, t.token_name
        )));
    }
    for (scheme, _) in &unlocked {
        notes.note(format_args!("{t} also has a {scheme} identity the lock does not record; `realise` adds it"));
    }
    // Locked schemes not checked now: unknown to this cakeys (e.g. from a newer one), or not
    // computable for this spec on this token.
    for scheme in locked.into_iter().flat_map(|ids| ids.keys()).filter(|s| !r.ids.contains_key(*s)) {
        if Scheme::from_name(scheme).is_some() {
            notes.note(format_args!(
                "{t} is not checked by its {scheme} identity here (not computable for this spec on this token)"
            ));
        } else {
            notes.warn(format_args!(
                "the lock records a {scheme} identity for '{}' that this cakeys does not know; it is not checked",
                t.object_name
            ));
        }
    }
    Ok(())
}

/// Record `r` in the lock: the object's type, commitment label and IDs it lacks, this
/// realisation, and the pairs. Never overwrites an ID. Whether the lock changed.
///
/// A realisation already in the lock is replaced, and every difference `compare` would have
/// refused without the write is said, one line each: the lock's diff is the review, so nothing
/// enters it unannounced. What keys.toml changed is a note; what changed on the token, which
/// nobody edited, is a warning.
fn record(t: &Target, r: &Resolved, lock: &mut Lock, facts: &Facts, notes: &mut Notes) -> Result<bool> {
    let mut changed = false;
    // One object per material (checked again on load): refuse to record the same material
    // under a second name.
    let class = t.object.class;
    for (name, o) in lock
        .objects
        .iter()
        .filter(|(n, o)| *n != t.object_name && o.object_type.as_ref().is_some_and(|ty| ty.class == class))
    {
        if let Some((s, _)) = r
            .ids
            .iter()
            .find(|(s, v)| !(class == Class::Certificate && *s == Scheme::Rfc7093m4.name()) && o.ids.get(*s) == Some(v))
        {
            return Err(KmError::PreconditionFailed(format!(
                "{t} is the same material as object '{name}' ({s}); use that object instead of a second name"
            )));
        }
    }
    let entry = lock.objects.entry(t.object_name.into()).or_default();
    if entry.object_type.is_none() {
        entry.object_type = Some(t.object.clone());
        changed = true;
    }
    if let Some(label) = &r.commitment_label
        && entry.commitment_label.as_ref().is_none_or(|l| l != label)
    {
        entry.commitment_label = Some(label.clone());
        changed = true;
    }
    for (scheme, got) in &r.ids {
        if Scheme::from_name(scheme).is_some_and(Scheme::is_deprecated) && !entry.ids.contains_key(scheme) {
            notes.note(format_args!(
                    "{t} also computes a {scheme} identity; not recorded: that computation is deprecated (docs/DESIGN.md §3.1)"
                ));
            continue;
        }
        if !entry.ids.contains_key(scheme) {
            entry.ids.insert(scheme.clone(), got.clone());
            changed = true;
        }
    }
    let real = LockRealisation {
        object: t.object_name.to_owned(),
        locator: t.on_token.locator.clone(),
        spec_digest: r.spec_digest.clone(),
        mode: r.mode,
        schemes: r.ids.keys().cloned().collect(),
        public_only: r.public_only,
        binding: r.binding,
        attestation: r.attestation.clone(),
        policy: r.policy.clone(),
        immutables: r.immutables.clone(),
        observed: Some(facts.observed.clone()),
        provenance: Some(facts.provenance.clone()),
    };
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        for d in spec_diff(t, r, prev) {
            notes.note(format_args!("re-recorded {t}: {d} (keys.toml)"));
        }
        for d in object_diff(r, prev) {
            notes.warn(format_args!("re-recorded {t}: {d} (changed on the token)"));
        }
        for (n, now) in r.policy.iter().filter(|(n, _)| !prev.policy.contains_key(*n)) {
            notes.note(format_args!("re-recorded {t}: {n} {now}, which the lock did not record"));
        }
    }
    let slot = lock.realisations.entry(t.spec_name.into()).or_default();
    if slot.get(t.token_name) != Some(&real) {
        slot.insert(t.token_name.into(), real);
        changed = true;
    }
    // Partners in this file are recomputed; listed ones from other fragments are kept.
    let pairs = lock.computed_pairs();
    let present: Vec<String> = lock.objects.keys().cloned().collect();
    for (name, o) in &mut lock.objects {
        let mut want = pairs.get(name).cloned().unwrap_or_default();
        want.extend(o.pairs.iter().filter(|p| !present.contains(p)).cloned());
        if o.pairs != want {
            o.pairs = want;
            changed = true;
        }
    }
    Ok(changed)
}

/// `observed` and `provenance` never change a verdict: identity is enforced by the CA-IDs, so a
/// different module build or token only warns. `realise` re-binds them.
#[expect(clippy::many_single_char_names, reason = "the prev/now module and token pairs stay short")]
fn warn_provenance(t: &Target, prev: &LockRealisation, now: &Facts, notes: &mut Notes) {
    if prev.observed.as_ref().is_some_and(|o| o.session == Session::User) && now.observed.session != Session::User {
        notes.warn(format_args!(
            "{t} was realised in a user session; this public session cannot see other private keys under its CKA_ID"
        ));
    }
    if let Some(o) = &prev.observed {
        let gone: Vec<&str> =
            o.mechanisms.iter().filter(|m| !now.observed.mechanisms.contains(m)).map(String::as_str).collect();
        if !gone.is_empty() {
            notes.warn(format_args!(
                "{t} was realised where the token offered {}, which it no longer does (functions.<token> in Nix)",
                gone.join(", ")
            ));
        }
    }
    let Some(p) = &prev.provenance else { return };
    let n = &now.provenance;
    if p.provider != n.provider {
        notes.warn(format_args!("{t} was realised with provider {}, now {}", p.provider, n.provider));
    }
    if p.cakeys_version != n.cakeys_version {
        notes.note(format_args!("{t} was realised by cakeys {}, now {}", p.cakeys_version, n.cakeys_version));
    }
    let (m, nm) = (&p.module, &n.module);
    if !m.same_build_identity(nm) {
        notes.warn(format_args!(
            "{t} was realised with module {} {} ({}), now {} {} ({})",
            m.description, m.version, m.manufacturer, nm.description, nm.version, nm.manufacturer
        ));
    } else if m.path != nm.path {
        notes.note(format_args!("{t} was realised with module file {}, now {}", m.path, nm.path));
    } else if let (Some(was), Some(now)) = (&m.hash, &nm.hash)
        && was != now
    {
        // Same file name, other content: replaced in place, which a path outside the Nix store
        // cannot show.
        notes.warn(format_args!("{t} was realised with module file {} of hash {was}, now {now}", m.path));
    }
    let (k, nk) = (&p.token, &n.token);
    if k != nk {
        notes.warn(format_args!(
            "{t} was realised on token {} #{} (firmware {}), now {} #{} (firmware {})",
            k.model, k.serial, k.firmware, nk.model, nk.serial, nk.firmware
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ModuleInfo, TokenInfo};

    const SRI_A: &str = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const SRI_B: &str = "sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=";

    fn config() -> Config {
        toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" } }\n",
        )
        .unwrap()
    }

    fn resolved(t: &Target) -> Resolved {
        Resolved {
            object: "k".into(),
            spec: "s".into(),
            token: "t".into(),
            uri: "pkcs11:token=t;object=k;type=private".into(),
            mode: Mode::Direct,
            public_only: false,
            spec_digest: id::spec_digest(t.object, t.spec),
            ids: [("rfc7093m4".to_owned(), SRI_A.to_owned())].into(),
            binding: Some(Binding::PopSign),
            assurance: crate::plan::Assurance::Proof,
            policy: [("CKA_SIGN".to_owned(), AttrValue::Bool(true))].into(),
            immutables: Immutables { local: Some(true), ..Default::default() },
            commitment_label: None,
            attestation: None,
        }
    }

    fn facts(module_version: &str) -> Facts {
        Facts {
            observed: Observed {
                uri: "pkcs11:token=t".into(),
                session: Session::User,
                mechanisms: vec!["CKM_ECDSA".into()],
            },
            provenance: Provenance {
                provider: "generic".into(),
                cakeys_version: "0.1.0".into(),
                module: ModuleInfo {
                    path: "/m.so".into(),
                    hash: None,
                    description: "m".into(),
                    manufacturer: "x".into(),
                    version: module_version.into(),
                    cryptoki: "3.0".into(),
                },
                token: TokenInfo { model: "m".into(), serial: "1".into(), firmware: "1.0".into() },
            },
        }
    }

    fn empty_lock() -> Lock {
        Lock { version: crate::config::LOCK_VERSION, ..Default::default() }
    }

    /// First use fails like a FOD (10, `<none>`) when only comparing; recording fills the lock,
    /// after which the same realisation compares clean and records nothing new.
    #[test]
    fn first_use_then_record_then_compare() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let r = resolved(&t);
        let mut lock = empty_lock();
        let mut notes = Notes::default();
        let err = compare(&t, &r, &lock, &facts("1"), LockWrite::Compare, &mut notes).unwrap_err();
        assert!(matches!(err, KmError::HashMismatch { ref expected, .. } if expected == "<none>"), "{err}");
        assert!(reconcile(&t, &r, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap());
        assert_eq!(lock.objects["k"].ids["rfc7093m4"], SRI_A);
        assert_eq!(lock.realisation("s", "t").unwrap().observed.as_ref().unwrap().session, Session::User);
        assert!(!reconcile(&t, &r, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap(), "nothing new");
        compare(&t, &r, &lock, &facts("1"), LockWrite::Compare, &mut notes).unwrap();
        assert!(notes.lines().is_empty(), "{:?}", notes.lines());
    }

    /// Drift the write is for (a changed spec, policy) fails only a compare; a downgrade, a
    /// replaced object, a mismatch and an attestation change fail a write too.
    #[test]
    fn what_a_write_may_and_may_not_override() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        let mut notes = Notes::default();
        let base = resolved(&t);
        reconcile(&t, &base, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap();
        let check = |r: &Resolved, write| compare(&t, r, &lock, &facts("1"), write, &mut Notes::default());

        let drifted = Resolved { spec_digest: SRI_B.into(), ..resolved(&t) };
        assert!(
            matches!(check(&drifted, LockWrite::Compare), Err(KmError::PreconditionFailed(m)) if m.contains("changed in keys.toml"))
        );
        check(&drifted, LockWrite::Record).unwrap();

        let policy = Resolved { policy: [("CKA_SIGN".to_owned(), AttrValue::Bool(false))].into(), ..resolved(&t) };
        assert!(
            matches!(check(&policy, LockWrite::Compare), Err(KmError::PreconditionFailed(m)) if m.contains("changed on the token"))
        );
        check(&policy, LockWrite::Record).unwrap();

        let weaker = Resolved { binding: Some(Binding::TokenAsserted), ..resolved(&t) };
        let replaced = Resolved { immutables: Immutables { local: Some(false), ..Default::default() }, ..resolved(&t) };
        let other = Resolved { ids: [("rfc7093m4".to_owned(), SRI_B.to_owned())].into(), ..resolved(&t) };
        for write in [LockWrite::Compare, LockWrite::Record] {
            assert!(
                matches!(check(&weaker, write), Err(KmError::PreconditionFailed(m)) if m.contains("binding downgrade"))
            );
            assert!(
                matches!(check(&replaced, write), Err(KmError::PreconditionFailed(m)) if m.contains("was replaced"))
            );
            assert!(matches!(check(&other, write), Err(KmError::HashMismatch { .. })));
        }
    }

    /// What a write accepts, it says: a changed spec is a note, a policy attribute that changed on
    /// the token a warning, and an unchanged realisation says nothing.
    #[test]
    fn a_write_says_what_it_rerecorded() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        reconcile(&t, &resolved(&t), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        let drifted = Resolved {
            spec_digest: SRI_B.into(),
            policy: [("CKA_SIGN".to_owned(), AttrValue::Bool(false)), ("CKA_UNWRAP".to_owned(), AttrValue::Bool(true))]
                .into(),
            ..resolved(&t)
        };
        let mut notes = Notes::default();
        assert!(reconcile(&t, &drifted, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap());
        let lines = notes.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].starts_with("note: re-recorded") && lines[0].contains("spec digest"), "{lines:?}");
        assert!(
            lines[1].starts_with("warning: re-recorded") && lines[1].contains("CKA_SIGN true -> false"),
            "{lines:?}"
        );
        assert!(lines[2].starts_with("note: re-recorded") && lines[2].contains("CKA_UNWRAP true"), "{lines:?}");
        let mut again = Notes::default();
        assert!(!reconcile(&t, &drifted, &mut lock, &facts("1"), LockWrite::Record, &mut again).unwrap());
        assert!(again.lines().is_empty(), "{:?}", again.lines());
    }

    /// A pinned attestation is compared even when writing: another anchor is a different device
    /// (14), another ID under the same anchor a changed object (10), none at all a downgrade (14).
    #[test]
    fn attestation_changes_are_never_rerecorded() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let attested = |root: &str, id: &str| Resolved {
            attestation: Some(AttestationRecord { kind: "yubico-piv".into(), root: root.into(), id: id.into() }),
            ..resolved(&t)
        };
        let mut lock = empty_lock();
        reconcile(&t, &attested(SRI_A, SRI_A), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default())
            .unwrap();
        let check = |r: &Resolved| compare(&t, r, &lock, &facts("1"), LockWrite::Record, &mut Notes::default());
        assert!(matches!(check(&attested(SRI_B, SRI_A)), Err(KmError::PreconditionFailed(m)) if m.contains("anchor")));
        assert!(matches!(check(&attested(SRI_A, SRI_B)), Err(KmError::HashMismatch { .. })));
        assert!(
            matches!(check(&resolved(&t)), Err(KmError::PreconditionFailed(m)) if m.contains("no longer computes"))
        );
    }

    /// Provenance never changes a verdict: a different module build is a warning in the notes.
    #[test]
    fn provenance_changes_only_warn() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        reconcile(&t, &resolved(&t), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        let mut notes = Notes::default();
        compare(&t, &resolved(&t), &lock, &facts("2"), LockWrite::Compare, &mut notes).unwrap();
        assert!(
            notes.lines().iter().any(|l| l.starts_with("warning: ") && l.contains("realised with module m 1")),
            "{:?}",
            notes.lines()
        );
    }

    /// The module file's hash: other content at the same path warns (replaced in place, which a
    /// path outside the Nix store cannot show); another path is a note, as a Nix rebuild.
    #[test]
    fn a_module_replaced_in_place_warns() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let with = |path: &str, hash: &str| {
            let mut f = facts("1");
            f.provenance.module.path = path.into();
            f.provenance.module.hash = Some(hash.into());
            f
        };
        let mut lock = empty_lock();
        reconcile(&t, &resolved(&t), &mut lock, &with("/m.so", SRI_A), LockWrite::Record, &mut Notes::default())
            .unwrap();
        let notes = |f: &Facts| {
            let mut n = Notes::default();
            compare(&t, &resolved(&t), &lock, f, LockWrite::Compare, &mut n).unwrap();
            n.lines().to_vec()
        };
        assert_eq!(notes(&with("/m.so", SRI_A)), Vec::<String>::new());
        let replaced = notes(&with("/m.so", SRI_B));
        assert!(replaced.iter().any(|l| l.starts_with("warning: ") && l.contains("of hash")), "{replaced:?}");
        let moved = notes(&with("/rebuilt/m.so", SRI_B));
        assert!(!moved.is_empty() && moved.iter().all(|l| l.starts_with("note: ")), "{moved:?}");
    }
}
