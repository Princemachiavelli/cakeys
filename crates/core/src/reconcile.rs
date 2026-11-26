//! The lock rules: compare what a token holds (a [`Resolved`]) with what the lock records, and
//! record what the lock lacks. Pure — no token access — so every rule is unit-testable. What a
//! run has to say besides its verdict (drift it tolerates, provenance changes, unchecked
//! schemes) goes into [`Notes`], which the caller prints whether or not the run succeeded.

use crate::config::{
    AttestationRecord, AttrValue, Binding, Immutables, KeyOrigin, Lock, LockRealisation, Mode, ModuleInfo, Observation,
    Observed, Origin, Provenance, Session,
};
use crate::id::{self, Scheme};
use crate::plan::Target;
use crate::types::ObjectClass as Class;
use crate::{KmError, Result};
use serde::Serialize;
use std::collections::BTreeMap;

/// What a token holds for one (spec, token) pair, as a run computed it: the object found, its
/// IDs and what was observed of it. `lock` and `check` print it as JSON.
#[derive(Debug, Serialize)]
pub struct Resolved {
    /// The object's name.
    pub object: String,
    /// The spec's name.
    pub spec: String,
    /// The token's name.
    pub token: String,
    /// RFC 7512 URI of the object found.
    pub uri: String,
    /// The identity mode the IDs were computed in.
    pub mode: Mode,
    /// Adopted through its public key object only (`publicOnly`).
    #[serde(rename = "publicOnly")]
    pub public_only: bool,
    /// SRI digest of the spec (object type and policy attributes).
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
    /// The IDs computed, scheme name -> SRI hash.
    pub ids: BTreeMap<String, String>,
    /// Private keys: how the private object was bound to `ids` (proven when `pop-sign`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// What the check establishes against a token that may lie: a fresh proof, a replayable
    /// fingerprint, or public bytes (`plan::assurance`; derived, never in the lock).
    pub assurance: crate::plan::Assurance,
    /// The observed policy vector and immutables of the object found (§4.2 of docs/DESIGN.md).
    pub policy: BTreeMap<String, AttrValue>,
    /// Attributes fixed when the object was made.
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
    /// A transport key's canonical SPKI (`Target::transport`), for the lock's `publicKey`.
    #[serde(skip)]
    pub public_key: Option<Vec<u8>>,
}

/// What a run has to say besides its verdict, in order. A command line's notes
/// ([`Notes::streaming`]) go to stderr as they are said, so a run killed part-way has said
/// everything up to there, in the order it happened (review 2026-11-23 C-7); a library caller's
/// and a test's are kept ([`Notes::lines`]).
#[derive(Debug, Default)]
pub struct Notes {
    lines: Vec<String>,
    streaming: bool,
    lock_written: bool,
}

impl Notes {
    /// Notes that are printed to stderr as each is said, and kept as well.
    #[must_use]
    pub fn streaming() -> Notes {
        Notes { streaming: true, ..Notes::default() }
    }

    fn push(&mut self, line: String) {
        if self.streaming {
            eprintln!("{line}");
        }
        self.lines.push(line);
    }

    /// A line as is (`created …`, `updated …`).
    pub fn say(&mut self, line: impl Into<String>) {
        self.push(line.into());
    }

    /// A `note:` line: something worth knowing that changes no verdict.
    pub fn note(&mut self, msg: impl std::fmt::Display) {
        self.push(format!("note: {msg}"));
    }

    /// A `warning:` line: drift or a change the run tolerates, but should be looked at.
    pub fn warn(&mut self, msg: impl std::fmt::Display) {
        self.push(format!("warning: {msg}"));
    }

    /// Every line so far, in order.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The run wrote the lock (created or changed it), at `path`: said, and a run that otherwise
    /// succeeds exits [`LOCK_WRITTEN`](crate::LOCK_WRITTEN), not 0.
    pub fn lock_written(&mut self, path: &std::path::Path) {
        self.lock_written = true;
        self.say(format!("updated {}", path.display()));
    }

    /// Whether [`Self::lock_written`] was said.
    #[must_use]
    pub fn wrote_lock(&self) -> bool {
        self.lock_written
    }
}

/// Whether a run records what the lock lacks (`lock`, `delete` by default) or only compares
/// (`lock --dry-run`, `create --no-update-lock`, and always for `check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockWrite {
    /// Only compare with the lock.
    Compare,
    /// Compare, then record what the lock lacks.
    Record,
}

/// What this run observed of the object and of the token: recorded on `lock`, compared
/// (warnings only) with what the lock recorded.
pub struct Facts {
    /// What was seen of the object (its URI, the session).
    pub observed: Observed,
    /// What the run saw of the module and token, recorded as an `observations` entry.
    pub observation: Observation,
    /// Where an imported object came from (docs/CAMIGRATE.md D7), for the realisation camigrate records
    /// right after the import; `None` for every other run, which keeps what the lock recorded.
    pub origin: Option<Origin>,
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
/// than the lock pins, `FirstUse` when it pins none to compare with under `LockWrite::Compare`,
/// `PreconditionFailed` for a realisation that moved (type, downgrade, replaced object,
/// attestation anchor); and `PreconditionFailed` for an import (`facts.origin`) of an object the
/// lock pins no IDs for.
pub fn reconcile(
    t: &Target,
    r: &Resolved,
    lock: &mut Lock,
    facts: &Facts,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<bool> {
    // An import is checked against the IDs its source recorded: without them it would be a first
    // use, recording whatever the target holds (docs/CAMIGRATE.md D6). A pair whose material is
    // born in a file is that first use (docs/FILE.md F3).
    if facts.origin.is_some()
        && t.on_token.key_origin() != KeyOrigin::File
        && lock.objects.get(t.object_name).is_none_or(|o| o.ids.is_empty())
    {
        return Err(KmError::PreconditionFailed(
            format!(
                "{t}: an import needs the IDs the lock pins for object '{}', and it pins none; lock it on \
             its source first",
                t.object_name
            )
            .into(),
        ));
    }
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
/// `FirstUse` (18) when it pins none and the write is off; `PreconditionFailed` (14) for a
/// type change, a downgrade, a replaced object, an attestation anchor change, or matching
/// material whose realisation the lock does not record.
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
    // so say so instead of reporting a hash mismatch (also when updating). A `modulusBits`
    // declared since is a gap `record_object` fills, not another type (review 2026-11-23 A-5).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref())
        && !locked.same_type(t.object.cfg())
    {
        return Err(KmError::PreconditionFailed(
            format!(
                "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
             different material needs a new object name",
                t.object_name,
                locked,
                t.object.cfg()
            )
            .into(),
        ));
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        if !update {
            spec_unchanged(t, r, prev)?;
        }
        // A spec pointed at another object (a keys.toml change `lock` re-records) realises that
        // object afresh: what the old one proved, or was made as, says nothing of the new one.
        if prev.object == t.object_name {
            no_downgrade(t, r, prev, update, notes)?;
        }
        if !update {
            object_unchanged(t, r, prev, notes)?;
        }
        warn_observed(t, prev, lock, facts, notes);
    }
    same_object_no_weaker(t, r, lock, update)?;
    let unlisted = lock.unlisted_pairs(t.object_name);
    if !update && !unlisted.is_empty() {
        notes.note(format_args!(
            "{unlisted:?} share the public key of '{}' but are not listed as its pairs; `lock` records them",
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
    Err(KmError::PreconditionFailed(
        format!(
            "spec '{}' changed in keys.toml since it was realised on '{}' ({}); review the change, then `lock`",
            t.spec_name,
            t.token_name,
            diff.join(", ")
        )
        .into(),
    ))
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

/// What the realisation proved when it was locked, it must still prove — also when `lock`
/// writes the lock: its mode, binding, attestation and schemes, and the immutables fixed when the
/// object was made.
/// The token object another spec already realised (the same object, token and locator, both
/// through the private object or both `publicOnly`: the same PKCS#11 object) holds this spec
/// to what that one established, as its own earlier realisation would: a second spec is no way
/// to record it without its attestation, its proof or its mode, when writing too (review
/// 2026-11-23 A-2). Another locator is another object of the same material, which may differ
/// (keys.toml's `shared-a` signs, `shared-b` does not).
fn same_object_no_weaker(t: &Target, r: &Resolved, lock: &Lock, update: bool) -> Result<()> {
    let others = lock
        .realisations
        .iter()
        .filter(|(spec, _)| spec.as_str() != t.spec_name)
        .filter_map(|(spec, on)| Some((spec, on.get(t.token_name)?)))
        .filter(|(_, prev)| {
            prev.object == t.object_name && prev.locator == t.on_token.locator && prev.public_only == r.public_only
        });
    for (spec, prev) in others {
        // What this one adds (an attestation the other lacks) is that realisation's to record.
        no_downgrade(t, r, prev, update, &mut Notes::default()).map_err(|e| match e {
            KmError::PreconditionFailed(m) => KmError::PreconditionFailed(
                format!(
                    "{m} (as spec '{spec}' realised the same object on '{}' under {}; a weaker realisation \
                     needs a new object name)",
                    t.token_name, prev.locator
                )
                .into(),
            ),
            other => other,
        })?;
    }
    Ok(())
}

fn no_downgrade(t: &Target, r: &Resolved, prev: &LockRealisation, update: bool, notes: &mut Notes) -> Result<()> {
    if r.mode.rank() > prev.mode.rank() {
        return Err(KmError::PreconditionFailed(
            format!("identity downgrade for {}: locked mode '{}', now only '{}'", t, prev.mode, r.mode).into(),
        ));
    }
    if let (Some(was), Some(now)) = (prev.binding, r.binding)
        && now.rank() > was.rank()
    {
        return Err(KmError::PreconditionFailed(
            format!("binding downgrade for {t}: locked binding '{was}', now only '{now}'").into(),
        ));
    }
    // The attestation is compared, even when lock writes the lock (§3.7). A different anchor means
    // a different device (or a re-provisioned TPM) signed the provenance; a different ID
    // under the same anchor means the attested object changed (re-imported, other
    // attributes or policy). Both are changes to review, never to re-record — and a lost
    // attestation is a scheme downgrade.
    match (&prev.attestation, &r.attestation) {
        (Some(was), Some(now)) if was.kind != now.kind || was.root != now.root => {
            return Err(KmError::PreconditionFailed(
                format!(
                    "attestation anchor for {} changed since it was realised ({} root {}, now {} root {}); \
                 the material needs a new object name",
                    t, was.kind, was.root, now.kind, now.root
                )
                .into(),
            ));
        }
        (Some(was), Some(now)) if was.id != now.id => {
            return Err(KmError::HashMismatch {
                what: format!("{} ({} attestation)", t, was.kind),
                expected: was.id.clone(),
                got: now.id.clone(),
            });
        }
        (Some(was), None) => {
            return Err(KmError::PreconditionFailed(
                format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it no longer computes",
                    t, was.kind
                )
                .into(),
            ));
        }
        (None, Some(now)) if !update => {
            notes.note(format_args!(
                "{} also has a {} attestation the lock does not record; `lock` adds it",
                t, now.kind
            ));
        }
        _ => {}
    }
    let lost: Vec<&String> = prev.schemes.iter().filter(|s| !r.ids.contains_key(*s)).collect();
    if !lost.is_empty() {
        return Err(KmError::PreconditionFailed(
            format!("identity downgrade for {t}: it was realised with {lost:?}, which it no longer computes").into(),
        ));
    }
    // Fixed at creation: weaker now means the object was replaced (also when updating).
    let weakened = r.immutables.weakened_since(&prev.immutables);
    if !weakened.is_empty() {
        return Err(KmError::PreconditionFailed(
            format!(
                "{} was replaced since it was realised: {} no longer true; a new object needs a new name",
                t,
                weakened.join(", ")
            )
            .into(),
        ));
    }
    Ok(())
}

/// The token's object changed (policy set since, or another object with the same material):
/// review, like a changed spec.
fn object_unchanged(t: &Target, r: &Resolved, prev: &LockRealisation, notes: &mut Notes) -> Result<()> {
    let diff = object_diff(r, prev);
    if !diff.is_empty() {
        return Err(KmError::PreconditionFailed(
            format!("{} changed on the token since it was realised ({}); review, then `lock`", t, diff.join(", "))
                .into(),
        ));
    }
    let new: Vec<&String> = r.policy.keys().filter(|n| !prev.policy.contains_key(*n)).collect();
    if !new.is_empty() {
        notes.note(format_args!("{t} also reports {new:?}, which the lock does not record; `lock` adds them"));
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

/// The IDs against the object's locked ones: a mismatch is 10, a first use when only comparing
/// 18; then the realisation itself must be locked (14). Notes what is not checked.
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
        return Err(KmError::PreconditionFailed(
            format!(
                "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
             material; lock a spec that computes both first",
                t,
                r.ids.keys().collect::<Vec<_>>(),
                t.object_name,
                ids.keys().collect::<Vec<_>>()
            )
            .into(),
        ));
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
        return Err(KmError::FirstUse { what: t.to_string(), got: (*got).clone() });
    }
    // The material matches, but the lock does not say this spec is realised on this token: the
    // lock describes where objects live, not only what they are.
    if !update && lock.realisation(t.spec_name, t.token_name).is_none() {
        return Err(KmError::PreconditionFailed(
            format!(
                "{} matches the locked identity, but the lock records no realisation of spec '{}' on \
             token '{}'; review, then `lock`",
                t, t.spec_name, t.token_name
            )
            .into(),
        ));
    }
    for (scheme, _) in &unlocked {
        // `record_object` does not add a deprecated scheme, so the note does not promise it.
        if Scheme::from_name(scheme).is_some_and(Scheme::is_deprecated) {
            notes.note(format_args!(
                "{t} also has a {scheme} identity the lock does not record; `lock` does not add it: that \
                 computation is deprecated (docs/DESIGN.md §3.1)"
            ));
        } else {
            notes.note(format_args!("{t} also has a {scheme} identity the lock does not record; `lock` adds it"));
        }
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

/// Record what the object's lock entry lacks: its type, commitment label, the IDs `r` computed
/// (never a deprecated one), and a transport key's public key. Whether it changed.
fn record_object(t: &Target, r: &Resolved, entry: &mut crate::config::LockObject, notes: &mut Notes) -> bool {
    let mut changed = false;
    match &mut entry.object_type {
        None => {
            entry.object_type = Some(t.object.cfg().clone());
            changed = true;
        }
        Some(ty) if ty.modulus_bits.is_none() && t.object.modulus_bits.is_some() => {
            ty.modulus_bits = t.object.modulus_bits;
            changed = true;
        }
        Some(_) => {}
    }
    // A recorded label stays: the IDs the lock holds were computed under it, and a run computes
    // with it (`commitment_label`), so only a gap is filled.
    if let Some(label) = &r.commitment_label
        && entry.commitment_label.is_none()
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
    // A transport key's public key, for exports from the lock alone. The SPKI hashes to the
    // rfc7093m4 just compared, which the load check holds a recorded one to: only a gap to fill.
    if let Some(spki) = &r.public_key
        && entry.public_key.is_none()
    {
        use base64::Engine as _;
        entry.public_key = Some(base64::engine::general_purpose::STANDARD.encode(spki));
        changed = true;
    }
    changed
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
            return Err(KmError::PreconditionFailed(
                format!("{t} is the same material as object '{name}' ({s}); use that object instead of a second name")
                    .into(),
            ));
        }
    }
    let entry = lock.objects.entry(t.object_name.into()).or_default();
    changed |= record_object(t, r, entry, notes);
    // The schemes that the object's IDs now hold. A deprecated scheme that `record_object` did not
    // record is left out, because a realisation names only schemes among its object's IDs, and a
    // lock that names another one does not load (`Lock::check`).
    let schemes = r.ids.keys().filter(|s| entry.ids.contains_key(*s)).cloned().collect();
    let real = LockRealisation {
        object: t.object_name.to_owned(),
        locator: t.on_token.locator.clone(),
        spec_digest: r.spec_digest.clone(),
        mode: r.mode,
        schemes,
        public_only: r.public_only,
        binding: r.binding,
        attestation: r.attestation.clone(),
        policy: r.policy.clone(),
        immutables: r.immutables.clone(),
        observation: Some(facts.observation.digest()),
        observed: Some(facts.observed.clone()),
        // The object's history: an import's `origin`, else what the lock recorded for this same
        // object (another object under the spec has another history).
        provenance: match &facts.origin {
            Some(o) => Some(Provenance { origin: Some(o.clone()) }),
            None => lock
                .realisation(t.spec_name, t.token_name)
                .filter(|prev| prev.object == t.object_name)
                .and_then(|prev| prev.provenance.clone()),
        },
    };
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        for d in spec_diff(t, r, prev) {
            notes.note(format_args!("re-recorded {t}: {d} (keys.toml)"));
        }
        // Another object's attributes differ from the old one's by nature, not by a change.
        for d in object_diff(r, prev).into_iter().filter(|_| prev.object == t.object_name) {
            notes.warn(format_args!("re-recorded {t}: {d} (changed on the token)"));
        }
        for (n, now) in r.policy.iter().filter(|(n, _)| !prev.policy.contains_key(*n)) {
            notes.note(format_args!("re-recorded {t}: {n} {now}, which the lock did not record"));
        }
    }
    // Keys are not recomputed on load, so an entry edited by hand may sit under this key: what
    // the run saw replaces it — but for the answers earlier runs and the probe recorded, which
    // are kept beside this run's (its own win).
    if let Some(key) = &real.observation {
        let mut seen = facts.observation.clone();
        if let Some(prev) = lock.observations.get(key) {
            let mut answers = prev.capabilities.clone();
            answers.append(&mut seen.capabilities);
            seen.capabilities = answers;
        }
        if lock.observations.get(key) != Some(&seen) {
            lock.observations.insert(key.clone(), seen);
            changed = true;
        }
    }
    let slot = lock.realisations.entry(t.spec_name.into()).or_default();
    if slot.get(t.token_name) != Some(&real) {
        slot.insert(t.token_name.into(), real);
        changed = true;
    }
    changed |= lock.drop_unreferenced_observations();
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

/// `observed` and the observation never change a verdict: identity is enforced by the CA-IDs, so
/// a different module build or token only warns. `lock` re-binds them.
fn warn_observed(t: &Target, prev: &LockRealisation, lock: &Lock, now: &Facts, notes: &mut Notes) {
    if prev.observed.as_ref().is_some_and(|o| o.session == Session::User) && now.observed.session != Session::User {
        notes.warn(format_args!(
            "{t} was realised in a user session; this public session cannot see other private keys under its CKA_ID"
        ));
    }
    let Some(p) = prev.observation.as_ref().and_then(|k| lock.observations.get(k)) else { return };
    let n = &now.observation;
    let gone: Vec<&str> = p.mechanisms.iter().filter(|m| !n.mechanisms.contains(m)).map(String::as_str).collect();
    if !gone.is_empty() {
        notes.warn(format_args!(
            "{t} was realised where the token offered {}, which it no longer does (functions.<token> in Nix)",
            gone.join(", ")
        ));
    }
    if !p.extra.is_empty() {
        let keys: Vec<&str> = p.extra.keys().map(String::as_str).collect();
        notes.warn(format_args!(
            "{t}: the lock records observations this cakeys does not know ({}); kept, not checked",
            keys.join(", ")
        ));
    }
    let none = || "(none)".to_owned();
    if let Some(was) = &p.provider
        && Some(was) != n.provider.as_ref()
    {
        notes.warn(format_args!(
            "{t} was realised with provider {was}, now {}",
            n.provider.clone().unwrap_or_else(none)
        ));
    }
    if let Some(was) = &p.cakeys_version
        && Some(was) != n.cakeys_version.as_ref()
    {
        notes.note(format_args!(
            "{t} was realised by cakeys {was}, now {}",
            n.cakeys_version.clone().unwrap_or_else(none)
        ));
    }
    if p.provider.is_some() && p.profile != n.profile {
        notes.note(format_args!(
            "{t} was realised under capability profile {}, now {}",
            p.profile.clone().unwrap_or_else(none),
            n.profile.clone().unwrap_or_else(none)
        ));
    }
    if let (Some(m), Some(nm)) = (&p.module, &n.module) {
        warn_module(t, m, nm, notes);
    }
    if let (Some(k), Some(nk)) = (&p.token, &n.token)
        && k != nk
    {
        notes.warn(format_args!(
            "{t} was realised on token {} #{} (firmware {}), now {} #{} (firmware {})",
            k.model, k.serial, k.firmware, nk.model, nk.serial, nk.firmware
        ));
    }
}

/// A different module build warns, another file of the same build is a note, and the same file
/// with other content (replaced in place) warns.
fn warn_module(t: &Target, m: &ModuleInfo, nm: &ModuleInfo, notes: &mut Notes) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Said, TokenInfo};

    const SRI_A: &str = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const SRI_B: &str = "sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=";

    fn config() -> Config {
        toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"adopt\" }\n",
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
            spec_digest: id::spec_digest(&t.object, t.spec),
            ids: [("rfc7093m4".to_owned(), SRI_A.to_owned())].into(),
            binding: Some(Binding::PopSign),
            assurance: crate::plan::Assurance::Proof,
            policy: [("CKA_SIGN".to_owned(), AttrValue::Bool(true))].into(),
            immutables: Immutables { local: Some(true), ..Default::default() },
            commitment_label: None,
            attestation: None,
            public_key: None,
        }
    }

    fn facts(module_version: &str) -> Facts {
        Facts {
            observed: Observed { uri: "pkcs11:token=t".into(), session: Session::User },
            observation: Observation {
                provider: Some("generic".into()),
                cakeys_version: Some("0.1.0".into()),
                profile: None,
                mechanisms: vec!["CKM_ECDSA".into()],
                module: Some(ModuleInfo {
                    path: "/m.so".into(),
                    hash: None,
                    description: "m".into(),
                    manufacturer: "x".into(),
                    version: module_version.into(),
                    cryptoki: "3.0".into(),
                }),
                token: Some(TokenInfo { model: "m".into(), serial: "1".into(), firmware: "1.0".into() }),
                capabilities: BTreeMap::new(),
                extra: BTreeMap::new(),
            },
            origin: None,
        }
    }

    fn empty_lock() -> Lock {
        Lock { version: crate::config::LOCK_VERSION, ..Default::default() }
    }

    /// First use fails like a FOD (18) when only comparing; recording fills the lock,
    /// after which the same realisation compares clean and records nothing new.
    #[test]
    fn first_use_then_record_then_compare() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let r = resolved(&t);
        let mut lock = empty_lock();
        let mut notes = Notes::default();
        let err = compare(&t, &r, &lock, &facts("1"), LockWrite::Compare, &mut notes).unwrap_err();
        assert!(matches!(err, KmError::FirstUse { ref got, .. } if got == SRI_A), "{err}");
        assert!(reconcile(&t, &r, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap());
        assert_eq!(lock.objects["k"].ids["rfc7093m4"], SRI_A);
        assert_eq!(lock.realisation("s", "t").unwrap().observed.as_ref().unwrap().session, Session::User);
        assert!(!reconcile(&t, &r, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap(), "nothing new");
        compare(&t, &r, &lock, &facts("1"), LockWrite::Compare, &mut notes).unwrap();
        assert!(notes.lines().is_empty(), "{:?}", notes.lines());
    }

    /// A deprecated scheme (docs/DESIGN.md §3.1) is never newly recorded. A first write and a
    /// second write record the other scheme that the realisation computes, add a note that the
    /// deprecated identity was not recorded, and leave a lock that loads again. An identity that
    /// the lock recorded under the scheme before it was deprecated still verifies, with a
    /// warning, and another value under it is still a mismatch (10). `Scheme::DEPRECATED` is
    /// empty, so the test marks `certhash` deprecated on its own thread (`DEPRECATED_IN_TEST`).
    #[test]
    fn a_deprecated_scheme_is_never_newly_recorded() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let ids = |cert: &str| [("rfc7093m4".to_owned(), SRI_A.to_owned()), ("certhash".to_owned(), cert.to_owned())];
        let both = Resolved { ids: ids(SRI_B).into(), ..resolved(&t) };
        let said = |notes: &Notes, what: &str| notes.lines().iter().any(|l| l.contains(what));
        let mut before = empty_lock();
        reconcile(&t, &both, &mut before, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        assert_eq!(before.objects["k"].ids.len(), 2, "recorded before the deprecation");

        id::DEPRECATED_IN_TEST.with(|d| d.set(Some(Scheme::Certhash)));
        let mut lock = empty_lock();
        for write in ["first", "second"] {
            let mut notes = Notes::default();
            reconcile(&t, &both, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap();
            let recorded: Vec<&String> = lock.objects["k"].ids.keys().collect();
            assert_eq!(recorded, ["rfc7093m4"], "the {write} write");
            assert!(said(&notes, "not recorded: that computation is deprecated"), "{:?}", notes.lines());
            let text = toml::to_string_pretty(&lock).unwrap();
            if let Err(e) = crate::config::parse_lock(&text, std::path::Path::new("keys.lock")) {
                panic!("the lock after the {write} write does not load: {e}");
            }
        }
        // A compare against that lock passes by rfc7093m4, and its note does not say that `lock`
        // adds the deprecated identity.
        let mut notes = Notes::default();
        compare(&t, &both, &lock, &facts("1"), LockWrite::Compare, &mut notes).unwrap();
        assert!(said(&notes, "`lock` does not add it"), "{:?}", notes.lines());
        assert!(!said(&notes, "`lock` adds it"), "{:?}", notes.lines());
        for write in [LockWrite::Compare, LockWrite::Record] {
            let mut notes = Notes::default();
            compare(&t, &both, &before, &facts("1"), write, &mut notes).unwrap();
            assert!(said(&notes, "uses a deprecated computation"), "{:?}", notes.lines());
            let other = Resolved { ids: ids(SRI_A).into(), ..resolved(&t) };
            let e = compare(&t, &other, &before, &facts("1"), write, &mut Notes::default()).unwrap_err();
            assert_eq!(e.exit_code(), 10, "{e}");
        }
        id::DEPRECATED_IN_TEST.with(|d| d.set(None));
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

    /// A second spec of the same token object (the same locator) cannot record it weaker than the
    /// first did, when writing too: without the attestation, or by `token-asserted`. As strong,
    /// it records. A spec with another locator realises another object of the same material,
    /// which may differ (review 2026-11-23 A-2).
    #[test]
    fn a_second_spec_of_the_same_object_cannot_record_it_weaker() {
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"adopt\" }\n\n\
             [specs.s2]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"adopt\" }\n\n\
             [specs.copy]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
             tokens.t = { locator = { CKA_LABEL = \"k-copy\" }, origin = \"adopt\" }\n",
        )
        .unwrap();
        let target = |spec: &'static str| Target::new(&cfg, spec, "t").unwrap();
        let (s, s2, copy) = (target("s"), target("s2"), target("copy"));
        let plain = |t: &Target| Resolved { spec: t.spec_name.to_owned(), ..resolved(t) };
        let attested = |t: &Target| Resolved {
            attestation: Some(AttestationRecord { kind: "yubico-piv".into(), root: SRI_A.into(), id: SRI_A.into() }),
            ..plain(t)
        };
        let mut lock = empty_lock();
        let mut record = |t: &Target, r: &Resolved| {
            reconcile(t, r, &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default())
        };
        record(&s, &attested(&s)).unwrap();
        let unattested = record(&s2, &plain(&s2)).unwrap_err();
        assert!(
            matches!(&unattested, KmError::PreconditionFailed(m)
                if m.contains("attestation") && m.contains("as spec 's' realised the same object")),
            "{unattested}"
        );
        let asserted = record(&s2, &Resolved { binding: Some(Binding::TokenAsserted), ..attested(&s2) }).unwrap_err();
        assert!(matches!(&asserted, KmError::PreconditionFailed(m) if m.contains("binding downgrade")), "{asserted}");
        record(&s2, &attested(&s2)).unwrap();
        record(&copy, &Resolved { binding: Some(Binding::TokenAsserted), ..plain(&copy) }).unwrap();
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

    /// An import records where the material came from (docs/CAMIGRATE.md D7); a later plain `lock` of
    /// the same object keeps it, and the lock still loads.
    #[test]
    fn an_import_records_its_origin_and_a_realise_keeps_it() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        let origin = Origin {
            from: "softhsm".into(),
            method: "public".into(),
            exposure: crate::migrate::Exposure::Public,
            declared: false,
        };
        let imported = Facts { origin: Some(origin.clone()), ..facts("1") };
        // Never a first use: without the IDs the source recorded nothing would check the material.
        let first = reconcile(&t, &resolved(&t), &mut lock, &imported, LockWrite::Record, &mut Notes::default());
        assert!(matches!(first, Err(KmError::PreconditionFailed(m)) if m.contains("an import needs the IDs")));
        assert!(lock.realisations.is_empty() && lock.objects.is_empty());
        lock.objects.insert(
            "k".into(),
            crate::config::LockObject {
                object_type: Some(t.object.cfg().clone()),
                ids: [("rfc7093m4".to_owned(), SRI_A.to_owned())].into(),
                ..Default::default()
            },
        );
        reconcile(&t, &resolved(&t), &mut lock, &imported, LockWrite::Record, &mut Notes::default()).unwrap();
        let recorded = |lock: &Lock| lock.realisation("s", "t").unwrap().provenance.clone();
        assert_eq!(recorded(&lock), Some(Provenance { origin: Some(origin.clone()) }));
        reconcile(&t, &resolved(&t), &mut lock, &facts("2"), LockWrite::Record, &mut Notes::default()).unwrap();
        assert_eq!(recorded(&lock), Some(Provenance { origin: Some(origin) }));
        let text = toml::to_string_pretty(&lock).unwrap();
        crate::config::parse_lock(&text, std::path::Path::new("keys.lock")).unwrap();
    }

    /// One entry per distinct observation (review A3): a re-record under another module build
    /// names a new entry and drops the one nothing names any more, and the object's history
    /// (`provenance.origin`) stays with the realisation.
    #[test]
    fn observations_are_pruned_and_origin_kept() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        let key = |lock: &Lock| lock.realisation("s", "t").unwrap().observation.clone().unwrap();
        reconcile(&t, &resolved(&t), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        let first = key(&lock);
        assert_eq!(first, facts("1").observation.digest());
        assert_eq!(lock.observations.keys().collect::<Vec<_>>(), [&first]);
        let origin = Provenance {
            origin: Some(Origin {
                from: "a".into(),
                method: "public".into(),
                exposure: crate::migrate::Exposure::Public,
                declared: false,
            }),
        };
        lock.realisations.get_mut("s").unwrap().get_mut("t").unwrap().provenance = Some(origin.clone());
        assert!(
            reconcile(&t, &resolved(&t), &mut lock, &facts("2"), LockWrite::Record, &mut Notes::default()).unwrap()
        );
        let second = key(&lock);
        assert_ne!(first, second);
        assert_eq!(lock.observations.keys().collect::<Vec<_>>(), [&second]);
        assert_eq!(lock.realisation("s", "t").unwrap().provenance, Some(origin));
        // An entry edited under its key is replaced by what the run saw.
        lock.observations.get_mut(&second).unwrap().mechanisms.clear();
        assert!(
            reconcile(&t, &resolved(&t), &mut lock, &facts("2"), LockWrite::Record, &mut Notes::default()).unwrap()
        );
        assert_eq!(lock.observations[&second], facts("2").observation);
    }

    /// What the token answered accumulates under one entry: the answers are no part of its key,
    /// and a run that records some keeps those earlier runs recorded (its own win).
    #[test]
    fn answers_accumulate_under_one_observation() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        let with = |answers: &[(&str, &str)]| {
            let mut f = facts("1");
            for (k, a) in answers {
                f.observation.capabilities.insert(
                    (*k).into(),
                    crate::config::Answered { answer: (*a).into(), ..crate::config::Answered::yes() },
                );
            }
            f
        };
        let record = |lock: &mut Lock, f: &Facts| {
            reconcile(&t, &resolved(&t), lock, f, LockWrite::Record, &mut Notes::default()).unwrap()
        };
        assert_eq!(
            with(&[("prove.pop-sign.CKK_EC.secp256r1", "yes")]).observation.digest(),
            facts("1").observation.digest()
        );
        record(&mut lock, &with(&[("prove.pop-sign.CKK_EC.secp256r1", "yes")]));
        record(&mut lock, &with(&[("generate.CKK_EC.secp256r1", "yes")]));
        // A run that recorded nothing new keeps what is there, and writes nothing.
        assert!(!record(&mut lock, &facts("1")));
        let [entry] = lock.observations.values().collect::<Vec<_>>()[..] else { panic!("one entry") };
        let keys: Vec<&str> = entry.capabilities.keys().map(String::as_str).collect();
        assert_eq!(keys, ["generate.CKK_EC.secp256r1", "prove.pop-sign.CKK_EC.secp256r1"]);
        record(&mut lock, &with(&[("generate.CKK_EC.secp256r1", "no")]));
        assert_eq!(
            lock.observations.values().next().unwrap().capabilities["generate.CKK_EC.secp256r1"].answer,
            Said::No
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
            let m = f.observation.module.as_mut().unwrap();
            m.path = path.into();
            m.hash = Some(hash.into());
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

    /// What a compare says without failing: an attestation the lock does not record yet (a
    /// note: `lock` adds it), a public session where the realisation was made in a user one,
    /// mechanisms the token no longer offers, and observation keys of a newer cakeys (warnings).
    /// A type that changed since it was locked fails, writing or not.
    #[test]
    fn a_compare_reports_what_changed_around_the_realisation() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        let mut was = facts("1");
        was.observation.extra.insert("future".into(), toml::Value::Boolean(true));
        reconcile(&t, &resolved(&t), &mut lock, &was, LockWrite::Record, &mut Notes::default()).unwrap();
        let mut now = facts("1");
        now.observed.session = Session::Public;
        now.observation.mechanisms.clear();
        let attested = Resolved {
            attestation: Some(AttestationRecord { kind: "tpm-certify".into(), root: SRI_A.into(), id: SRI_B.into() }),
            ..resolved(&t)
        };
        let mut notes = Notes::default();
        compare(&t, &attested, &lock, &now, LockWrite::Compare, &mut notes).unwrap();
        let said = notes.lines().join("\n");
        for line in [
            "note: 'k' (spec 's') on token 't' also has a tpm-certify attestation the lock does not record",
            "realised in a user session; this public session cannot see",
            "the token offered CKM_ECDSA, which it no longer does",
            "observations this cakeys does not know (future)",
        ] {
            assert!(said.contains(line), "expected {line:?} in\n{said}");
        }

        let mut retyped = lock.clone();
        retyped.objects.get_mut("k").unwrap().object_type.as_mut().unwrap().curve = Some("secp384r1".into());
        for write in [LockWrite::Compare, LockWrite::Record] {
            let e = compare(&t, &resolved(&t), &retyped, &facts("1"), write, &mut Notes::default()).unwrap_err();
            assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("changed since it was locked")), "{e}");
        }
    }

    /// A `modulusBits` declared after the lock recorded the type describes the same key: the
    /// changed spec is reviewed and `lock` records the size; another declared size is still
    /// another type (review 2026-11-23 A-5).
    #[test]
    fn a_declared_modulus_size_is_not_a_new_type() {
        let rsa = |bits: &str| -> Config {
            toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n\
                 [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\n{bits}\n\
                 [specs.s]\nobject = \"k\"\nattributes = {{ CKA_SIGN = true }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"k\" }}, origin = \"adopt\" }}\n",
            ))
            .unwrap()
        };
        let (bare, sized, other) = (rsa(""), rsa("modulusBits = 2048\n"), rsa("modulusBits = 3072\n"));
        let mut lock = empty_lock();
        let t = Target::new(&bare, "s", "t").unwrap();
        reconcile(&t, &resolved(&t), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();

        let t = Target::new(&sized, "s", "t").unwrap();
        let e = compare(&t, &resolved(&t), &lock, &facts("1"), LockWrite::Compare, &mut Notes::default()).unwrap_err();
        assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("changed in keys.toml")), "{e}");
        assert!(
            reconcile(&t, &resolved(&t), &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap()
        );
        assert_eq!(lock.objects["k"].object_type.as_ref().unwrap().modulus_bits, Some(2048));
        compare(&t, &resolved(&t), &lock, &facts("1"), LockWrite::Compare, &mut Notes::default()).unwrap();

        let t = Target::new(&other, "s", "t").unwrap();
        for write in [LockWrite::Compare, LockWrite::Record] {
            let e = compare(&t, &resolved(&t), &lock, &facts("1"), write, &mut Notes::default()).unwrap_err();
            assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("changed since it was locked")), "{e}");
        }
    }

    /// A second look at the same or a stronger realisation passes, writing or not: the same
    /// attestation, a stronger mode. A weaker mode is a downgrade (14). What the lock lacks is
    /// said when only comparing; a write records it without the note.
    #[test]
    fn the_same_or_more_passes_and_less_is_a_downgrade() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let record = |r: &Resolved| {
            let mut lock = empty_lock();
            reconcile(&t, r, &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
            lock
        };
        let said = |r: &Resolved, lock: &Lock, write| {
            let mut notes = Notes::default();
            compare(&t, r, lock, &facts("1"), write, &mut notes).map(|()| notes.lines().join("\n"))
        };
        let attested = Resolved {
            attestation: Some(AttestationRecord { kind: "yubico-piv".into(), root: SRI_A.into(), id: SRI_B.into() }),
            ..resolved(&t)
        };
        let lock = record(&attested);
        for write in [LockWrite::Compare, LockWrite::Record] {
            assert_eq!(said(&attested, &lock, write).unwrap(), "", "{write:?}");
        }
        let plain = record(&resolved(&t));
        let lacks = "attestation the lock does not record";
        assert!(said(&attested, &plain, LockWrite::Compare).unwrap().contains(lacks));
        assert!(!said(&attested, &plain, LockWrite::Record).unwrap().contains(lacks));

        let in_mode = |mode| Resolved { mode, ..resolved(&t) };
        let committed = record(&in_mode(Mode::Commitment));
        said(&in_mode(Mode::Direct), &committed, LockWrite::Record).unwrap();
        let e = said(&in_mode(Mode::WrapRebind), &committed, LockWrite::Record).unwrap_err();
        assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("locked mode 'commitment'")), "{e}");
    }

    /// A spec pointed at another object is a keys.toml change: 14 when only comparing, re-recorded
    /// with a note by a write. The old object's record judges nothing of the new one, so a new
    /// object that was imported where the old was generated, is unattested where the old was
    /// attested, and is bound more weakly, is neither a downgrade nor a change on the token (it
    /// was all three, and `lock` refused the retarget until the lock was edited by hand).
    #[test]
    fn a_retargeted_spec_is_judged_as_its_new_object() {
        let config = |object: &str| -> Config {
            toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n\
                 [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                 [objects.k2]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                 [specs.s]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"k\" }}, origin = \"adopt\" }}\n"
            ))
            .unwrap()
        };
        let (was, now) = (config("k"), config("k2"));
        let (a, b) = (Target::new(&was, "s", "t").unwrap(), Target::new(&now, "s", "t").unwrap());
        let mut lock = empty_lock();
        let attested = Resolved {
            attestation: Some(AttestationRecord { kind: "yubico-piv".into(), root: SRI_A.into(), id: SRI_A.into() }),
            ..resolved(&a)
        };
        reconcile(&a, &attested, &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        let other = Resolved {
            object: "k2".into(),
            ids: [("rfc7093m4".to_owned(), SRI_B.to_owned())].into(),
            binding: Some(Binding::TokenAsserted),
            immutables: Immutables { local: Some(false), ..Default::default() },
            ..resolved(&b)
        };
        let e = compare(&b, &other, &lock, &facts("1"), LockWrite::Compare, &mut Notes::default()).unwrap_err();
        assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("object 'k' -> 'k2'")), "{e}");
        let mut notes = Notes::default();
        assert!(reconcile(&b, &other, &mut lock, &facts("1"), LockWrite::Record, &mut notes).unwrap());
        let lines = notes.lines();
        assert!(
            lines.iter().any(|l| l.starts_with("note: re-recorded") && l.contains("object 'k' -> 'k2'")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.starts_with("warning:")), "{lines:?}");
        assert_eq!(lock.realisation("s", "t").unwrap().object, "k2");
        compare(&b, &other, &lock, &facts("1"), LockWrite::Compare, &mut Notes::default()).unwrap();
        // Back on the same object, a weaker mode is still a downgrade.
        let weaker = Resolved { mode: Mode::WrapRebind, ..other };
        let e = compare(&b, &weaker, &lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap_err();
        assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains("downgrade")), "{e}");
    }

    /// The lock's object entry: the commitment label it records is the one used from then on
    /// (the default until then) and is written once; a line said is a line in the notes.
    #[test]
    fn the_recorded_label_is_the_label_used() {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = empty_lock();
        assert_eq!(commitment_label(&t, &lock), id::DEFAULT_COMMITMENT_LABEL);
        let labelled = |label: &str| Resolved { commitment_label: Some(label.into()), ..resolved(&t) };
        let write = |r: &Resolved, lock: &mut Lock| {
            reconcile(&t, r, lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap()
        };
        assert!(write(&labelled("first"), &mut lock));
        assert_eq!(commitment_label(&t, &lock), "first");
        assert!(!write(&labelled("first"), &mut lock), "the same label is not written again");
        // A recorded label is never overwritten: the locked IDs were computed under it.
        assert!(!write(&labelled("second"), &mut lock), "a recorded label stays");
        assert_eq!(commitment_label(&t, &lock), "first");
        let mut notes = Notes::default();
        notes.say("created k");
        assert_eq!(notes.lines(), ["created k"]);
    }

    /// keys.toml with a second private key and two certificates beside `k`, each with a spec
    /// of its own name on `t`.
    fn family() -> Config {
        let mut text = "[tokens.t]\ntokenLabel = \"t\"\n\n".to_owned();
        for (name, ty) in [
            ("k", "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
            ("k2", "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
            ("c", "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\""),
            ("c2", "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\""),
        ] {
            use std::fmt::Write as _;
            write!(
                text,
                "[objects.{name}]\n{ty}\n\n[specs.{name}]\nobject = \"{name}\"\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"{name}\" }}, origin = \"adopt\" }}\n\n"
            )
            .unwrap();
        }
        toml::from_str(&text).unwrap()
    }

    /// One object per material within a class, held when recording: the same key under a second
    /// name is refused (14), as is the same certificate; a key and its certificates share the
    /// public key, are recorded in either order, and are listed as each other's pairs. Pairs
    /// from another lock fragment are kept; one in this file that shares no key is dropped.
    #[test]
    fn material_is_recorded_once_and_paired_by_its_public_key() {
        let cfg = family();
        let sri_c = id::sri(b"c");
        let write = |lock: &mut Lock, name: &str, ids: &[(&str, &str)]| {
            let t = Target::new(&cfg, name, "t").unwrap();
            let key = t.object.class == Class::PrivateKey;
            let r = Resolved {
                object: name.into(),
                spec: name.into(),
                ids: ids.iter().map(|(s, v)| ((*s).to_owned(), (*v).to_owned())).collect(),
                binding: key.then_some(Binding::PopSign),
                policy: BTreeMap::new(),
                immutables: Immutables::default(),
                ..resolved(&t)
            };
            reconcile(&t, &r, lock, &facts("1"), LockWrite::Record, &mut Notes::default())
        };
        let same = |e: KmError, other: &str, scheme: &str| {
            let want = format!("is the same material as object '{other}' ({scheme})");
            assert!(matches!(&e, KmError::PreconditionFailed(m) if m.contains(&want)), "{e}");
        };
        let (key, cert) = ([("rfc7093m4", SRI_A)], [("certhash", SRI_B), ("rfc7093m4", SRI_A)]);

        let mut lock = empty_lock();
        write(&mut lock, "k", &key).unwrap();
        same(write(&mut lock, "k2", &key).unwrap_err(), "k", "rfc7093m4");
        write(&mut lock, "c", &cert).unwrap();
        same(write(&mut lock, "c2", &cert).unwrap_err(), "c", "certhash");
        // Another certificate of the same key, and another key.
        write(&mut lock, "c2", &[("certhash", &sri_c), ("rfc7093m4", SRI_A)]).unwrap();
        write(&mut lock, "k2", &[("rfc7093m4", SRI_B)]).unwrap();
        let pairs = |lock: &Lock, name: &str| lock.objects[name].pairs.iter().cloned().collect::<Vec<_>>();
        assert_eq!(pairs(&lock, "k"), ["c", "c2"]);
        assert_eq!(pairs(&lock, "c2"), ["c", "k"]);
        assert_eq!(pairs(&lock, "k2"), [] as [String; 0]);

        // The certificate first, then its key.
        let mut other_order = empty_lock();
        write(&mut other_order, "c", &cert).unwrap();
        write(&mut other_order, "k", &key).unwrap();
        assert_eq!(pairs(&other_order, "c"), ["k"]);

        lock.objects.get_mut("k").unwrap().pairs.extend(["elsewhere".to_owned(), "k2".to_owned()]);
        assert!(write(&mut lock, "k", &key).unwrap());
        assert_eq!(pairs(&lock, "k"), ["c", "c2", "elsewhere"]);
    }

    /// Objects of this file that share the key and are not listed as pairs are named when
    /// comparing; a write lists them instead.
    #[test]
    fn unlisted_pairs_are_named_when_comparing() {
        let cfg = family();
        let t = Target::new(&cfg, "k", "t").unwrap();
        let r = Resolved { spec: "k".into(), ..resolved(&t) };
        let mut lock = empty_lock();
        reconcile(&t, &r, &mut lock, &facts("1"), LockWrite::Record, &mut Notes::default()).unwrap();
        let cert = crate::config::LockObject {
            object_type: Some(cfg.objects["c"].clone()),
            ids: [("certhash".to_owned(), SRI_B.to_owned()), ("rfc7093m4".to_owned(), SRI_A.to_owned())].into(),
            ..Default::default()
        };
        lock.objects.insert("c".into(), cert);
        let said = |write| {
            let mut notes = Notes::default();
            compare(&t, &r, &lock, &facts("1"), write, &mut notes).unwrap();
            notes.lines().join("\n")
        };
        let unlisted = "share the public key of 'k' but are not listed as its pairs";
        assert!(said(LockWrite::Compare).contains(unlisted), "{}", said(LockWrite::Compare));
        assert!(!said(LockWrite::Record).contains(unlisted));
    }
}
