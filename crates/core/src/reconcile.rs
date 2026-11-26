//! The lock rules. This module compares what a token holds (a [`Resolved`]) with what the lock
//! records, and it adds to the lock what the lock does not record yet. The module never accesses
//! a token, so a unit test can exercise every rule. The messages that a run prints in addition to
//! its result (drift that the run accepts, changes of provenance, and schemes that it did not
//! check) go into [`Notes`], and the caller prints them whether or not the run succeeded.

use crate::config::{
    AttestationRecord, AttrValue, Binding, Immutables, KeyOrigin, Lock, LockRealisation, Mode, ModuleInfo, Observation,
    Observed, Origin, Provenance, Session,
};
use crate::id::{self, Scheme};
use crate::plan::Target;
use crate::types::ObjectClass as Class;
use crate::{Check, KmError, Reason, Result};
use serde::Serialize;
use std::collections::BTreeMap;

/// What a run found on a token for one (spec, token) pair: the object that it found, the IDs
/// that it computed, and what it observed of the object. `lock` and `check` print it as JSON.
#[derive(Debug, Serialize)]
pub struct Resolved {
    /// The object's name.
    pub object: String,
    /// The spec's name.
    pub spec: String,
    /// The token's name.
    pub token: String,
    /// The RFC 7512 URI of the object that the run found.
    pub uri: String,
    /// The identity mode in which the run computed the IDs.
    pub mode: Mode,
    /// True when the run adopted the object through its public key object only (`publicOnly`).
    #[serde(rename = "publicOnly")]
    pub public_only: bool,
    /// The SRI digest of the spec (the object type and the policy attributes).
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
    /// The IDs that the run computed, as a map from the scheme name to the SRI hash.
    pub ids: BTreeMap<String, String>,
    /// For a private key: how the run bound the private object to `ids`. The binding is proven
    /// when it is `pop-sign`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// What the check establishes when the token may return false data: a fresh proof, a
    /// fingerprint that a token could replay, or public bytes. `plan::assurance` derives this
    /// value, and the lock never records it.
    pub assurance: crate::plan::Assurance,
    /// The policy attributes that the run observed on the object (§4.2 of docs/DESIGN.md).
    pub policy: BTreeMap<String, AttrValue>,
    /// The attributes that were fixed when the object was created.
    #[serde(skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    /// The label with which the run computed the commitment schemes in `ids`. It is `None` when
    /// all the IDs come from public material.
    #[serde(rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The attestation that the run computed for this realisation (§3.7), when the spec opted in.
    /// `kind` names the type of evidence, `root` names the anchor to which the evidence was
    /// verified, and `id` is the attestation ID of this device. The attestation is never in
    /// `ids`, because `ids` holds only the portable schemes that are the same on every token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
    /// The canonical SPKI of a transport key (`Target::transport`), which the lock records as
    /// `publicKey`.
    #[serde(skip)]
    pub public_key: Option<Vec<u8>>,
}

/// The messages that a run prints in addition to its result, in order. A command-line tool uses
/// [`Notes::streaming`], which prints each message to stderr when it is added. A run that is
/// killed partway through has therefore already printed every earlier message, in order (review
/// 2026-11-23 C-7). A library caller or a test keeps the messages and reads them with
/// [`Notes::lines`].
#[derive(Debug, Default)]
pub struct Notes {
    lines: Vec<String>,
    streaming: bool,
    lock_written: bool,
}

impl Notes {
    /// Creates notes that print each message to stderr when it is added, and that also keep it.
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

    /// Adds a line without a prefix (`created …`, `updated …`).
    pub fn say(&mut self, line: impl Into<String>) {
        self.push(line.into());
    }

    /// Adds a `note:` line: information that does not change the result of the run.
    pub fn note(&mut self, msg: impl std::fmt::Display) {
        self.push(format!("note: {msg}"));
    }

    /// Adds a `warning:` line: drift or a change that the run accepts, but that a person should
    /// review.
    pub fn warn(&mut self, msg: impl std::fmt::Display) {
        self.push(format!("warning: {msg}"));
    }

    /// Every line so far, in order.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Records that the run wrote (created or changed) the lock at `path`, and adds an `updated`
    /// line. The run then exits with [`LOCK_WRITTEN`](crate::LOCK_WRITTEN) (22) instead of 0, even
    /// if a later step of the run fails.
    pub fn lock_written(&mut self, path: &std::path::Path) {
        self.lock_written = true;
        self.say(format!("updated {}", path.display()));
    }

    /// Returns whether the run called [`Self::lock_written`].
    #[must_use]
    pub fn wrote_lock(&self) -> bool {
        self.lock_written
    }
}

/// Whether a run adds to the lock what the lock does not record yet (`lock`, and `delete` by
/// default) or only compares with the lock (`lock --dry-run`, `create --no-update-lock`, and every
/// `check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockWrite {
    /// Only compare with the lock.
    Compare,
    /// Compare with the lock, then add to the lock what it does not record yet.
    Record,
}

/// What this run observed of the object and of the token. `lock` records these facts. Every run
/// compares them with what the lock recorded, but a difference only produces a warning.
pub struct Facts {
    /// What the run saw of the object (its URI and the session).
    pub observed: Observed,
    /// What the run saw of the module and the token, recorded as an `observations` entry.
    pub observation: Observation,
    /// Where an imported object came from (docs/CAMIGRATE.md D7). camigrate sets it for the
    /// realisation that it records right after the import. It is `None` for every other run, and
    /// such a run keeps the origin that the lock already records.
    pub origin: Option<Origin>,
}

/// Returns the label with which to compute the commitments of `t`. That is the label that the
/// lock records for the object, or the default label (`id::DEFAULT_COMMITMENT_LABEL`) when the
/// lock records none.
#[must_use]
pub fn commitment_label(t: &Target, lock: &Lock) -> String {
    lock.objects
        .get(t.object_name)
        .and_then(|o| o.commitment_label.clone())
        .unwrap_or_else(|| id::DEFAULT_COMMITMENT_LABEL.to_owned())
}

/// Compares `r` with the lock. With `LockWrite::Record`, it then adds to the lock what the lock
/// does not record yet (see `record`). Returns whether the lock changed.
///
/// # Errors
///
/// Returns every error that `compare` returns: `HashMismatch` when the token's material hashes to
/// a different ID than the one that the lock pins, `FirstUse` when the lock pins no ID to compare
/// with and the write is `LockWrite::Compare`, and `PreconditionFailed` for a realisation that
/// changed (its type, a downgrade, a replaced object, or the attestation anchor). Also returns
/// `PreconditionFailed` for an import (`facts.origin` is set) of an object for which the lock pins
/// no IDs, unless the key's origin is a file.
pub fn reconcile(
    t: &Target,
    r: &Resolved,
    lock: &mut Lock,
    facts: &Facts,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<bool> {
    // An import is checked against the IDs that the lock recorded for its source. Without those
    // IDs, the import would be a first use, and the lock would record whatever the target token
    // holds (docs/CAMIGRATE.md D6). A pair whose material is created from a file is allowed to be
    // that first use (docs/FILE.md F3).
    if facts.origin.is_some()
        && t.on_token.key_origin() != KeyOrigin::File
        && lock.objects.get(t.object_name).is_none_or(|o| o.ids.is_empty())
    {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockImportIds,
            format!(
                "{t}: an import needs the IDs the lock pins for object '{}', and it pins none; lock it on \
             its source first",
                t.object_name
            ),
        )));
    }
    compare(t, r, lock, facts, write, notes)?;
    match write {
        LockWrite::Compare => Ok(false),
        LockWrite::Record => record(t, r, lock, facts, notes),
    }
}

/// Applies every rule that a realisation must pass against the lock. The rules run in a fixed
/// order, and the first rule that fails decides the exit code. With `LockWrite::Record`, a changed
/// spec, a changed policy and a first use pass here, because the write exists to record them, and
/// `record` reports what it accepted. A type change, a downgrade, a replaced object, a change of
/// the attestation anchor and a hash mismatch fail with either `LockWrite` value.
///
/// # Errors
///
/// Returns `HashMismatch` (10) when the token's material hashes to a different ID than the
/// one that the lock pins. Returns `FirstUse` (18) when the lock pins no ID and the write is
/// `LockWrite::Compare`. Returns `PreconditionFailed` (14) for a type change, a downgrade, a
/// replaced object, a change of the attestation anchor, or matching material whose realisation
/// the lock does not record, and, with `LockWrite::Compare`, for a changed spec or policy.
pub fn compare(
    t: &Target,
    r: &Resolved,
    lock: &Lock,
    facts: &Facts,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<()> {
    let update = write == LockWrite::Record;
    // The lock pins the object type for which its IDs were computed. A different type means
    // different material, so the run reports the type change instead of a hash mismatch, also
    // when it writes the lock. A `modulusBits` value that keys.toml declares after the lock was
    // written is not a different type: `record_object` adds it to the lock (review 2026-11-23 A-5).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref())
        && !locked.same_type(t.object.cfg())
    {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockType,
            format!(
                "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
             different material needs a new object name",
                t.object_name,
                locked,
                t.object.cfg()
            ),
        )));
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        if !update {
            spec_unchanged(t, r, prev)?;
        }
        // When keys.toml points a spec at another object (a change that `lock` records again), the
        // realisation of the new object starts fresh. What the old object proved, and how it was
        // created, do not apply to the new object, so the downgrade check is skipped.
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

/// Fails when keys.toml changed what this realisation is (another object, another locator,
/// `publicOnly`, or the policy), because a person must then review the change and record the
/// lock again.
fn spec_unchanged(t: &Target, r: &Resolved, prev: &LockRealisation) -> Result<()> {
    let diff = spec_diff(t, r, prev);
    if diff.is_empty() {
        return Ok(());
    }
    Err(KmError::PreconditionFailed(Reason::check(
        Check::LockSpec,
        format!(
            "spec '{}' changed in keys.toml since it was realised on '{}' ({}); review the change, then `lock`",
            t.spec_name,
            t.token_name,
            diff.join(", ")
        ),
    )))
}

/// Lists the differences between what keys.toml now declares for this realisation and what the
/// lock records.
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

/// Fails when another spec already realised the same PKCS#11 object on this token and this
/// realisation is weaker. The same PKCS#11 object means the same object name, token and locator,
/// with both realisations either through the private object or both `publicOnly`. This spec must
/// meet what the other realisation established, as it would have to meet its own earlier
/// realisation. Otherwise, a second spec could record the object without the attestation, the
/// proof or the mode of the first one. The rule applies also when the run writes the lock
/// (review 2026-11-23 A-2). A different locator selects a different object with the same
/// material, and that object may have different attributes (in
/// `crates/cli/tests/fixtures/keys.toml`, `shared-a` can sign and `shared-b` cannot).
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
        // The notes are discarded. When this realisation has something that the other one lacks,
        // such as an attestation, that is not an error, and this realisation's own record holds it.
        no_downgrade(t, r, prev, update, &mut Notes::default()).map_err(|e| match e {
            KmError::PreconditionFailed(m) => KmError::PreconditionFailed(Reason::check(
                Check::LockSameObject,
                format!(
                    "{m} (as spec '{spec}' realised the same object on '{}' under {}; a weaker realisation \
                     needs a new object name)",
                    t.token_name, prev.locator
                ),
            )),
            other => other,
        })?;
    }
    Ok(())
}

/// Fails when this realisation proves less than it proved when it was locked. That covers its
/// mode, its binding, its attestation and its schemes, and the immutables that were fixed when
/// the object was created. The rule applies also when `lock` writes the lock.
fn no_downgrade(t: &Target, r: &Resolved, prev: &LockRealisation, update: bool, notes: &mut Notes) -> Result<()> {
    if r.mode.rank() > prev.mode.rank() {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockMode,
            format!("identity downgrade for {}: locked mode '{}', now only '{}'", t, prev.mode, r.mode),
        )));
    }
    if let (Some(was), Some(now)) = (prev.binding, r.binding)
        && now.rank() > was.rank()
    {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockBinding,
            format!("binding downgrade for {t}: locked binding '{was}', now only '{now}'"),
        )));
    }
    // The attestation is compared even when `lock` writes the lock (§3.7). A different anchor
    // means that a different device (or a re-provisioned TPM) signed the provenance. A different
    // ID under the same anchor means that the attested object changed: it was imported again, or
    // its attributes or its policy changed. A person must review both changes, so the run refuses
    // them instead of recording them. A lost attestation is a downgrade of the schemes.
    match (&prev.attestation, &r.attestation) {
        (Some(was), Some(now)) if was.kind != now.kind || was.root != now.root => {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::LockAttestationAnchor,
                format!(
                    "attestation anchor for {} changed since it was realised ({} root {}, now {} root {}); \
                 the material needs a new object name",
                    t, was.kind, was.root, now.kind, now.root
                ),
            )));
        }
        (Some(was), Some(now)) if was.id != now.id => {
            return Err(KmError::HashMismatch {
                what: format!("{} ({} attestation)", t, was.kind),
                expected: was.id.clone(),
                got: now.id.clone(),
                check: Check::LockAttestationId,
            });
        }
        (Some(was), None) => {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::LockAttestationKept,
                format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it no longer computes",
                    t, was.kind
                ),
            )));
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
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockSchemesKept,
            format!("identity downgrade for {t}: it was realised with {lost:?}, which it no longer computes"),
        )));
    }
    // The immutables are fixed when the object is created, so a weaker value now means that the
    // object was replaced. This fails also when the run writes the lock.
    let weakened = r.immutables.weakened_since(&prev.immutables);
    if !weakened.is_empty() {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockImmutables,
            format!(
                "{} was replaced since it was realised: {} no longer true; a new object needs a new name",
                t,
                weakened.join(", ")
            ),
        )));
    }
    Ok(())
}

/// Fails when the object on the token changed since it was locked: a policy attribute was set
/// since then, or another object with the same material took its place. A person must review
/// this change, as for a changed spec. Also notes the policy attributes that the token now
/// reports and that the lock does not record.
fn object_unchanged(t: &Target, r: &Resolved, prev: &LockRealisation, notes: &mut Notes) -> Result<()> {
    let diff = object_diff(r, prev);
    if !diff.is_empty() {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockAttributes,
            format!("{} changed on the token since it was realised ({}); review, then `lock`", t, diff.join(", ")),
        )));
    }
    let new: Vec<&String> = r.policy.keys().filter(|n| !prev.policy.contains_key(*n)).collect();
    if !new.is_empty() {
        notes.note(format_args!("{t} also reports {new:?}, which the lock does not record; `lock` adds them"));
    }
    Ok(())
}

/// Lists the policy attributes and the immutables that now differ between the object on the
/// token and the lock's record.
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

/// Compares the IDs that the run computed with the IDs that the lock records for the object. It
/// fails with exit 14 when no computed scheme is among the locked schemes, with exit 10 on a
/// mismatch, and with exit 18 on a first use when the run only compares. The lock must then also
/// record the realisation itself, or the comparison fails with exit 14. A note or a warning names
/// each locked scheme that the run did not check.
fn compare_ids(t: &Target, r: &Resolved, lock: &Lock, update: bool, notes: &mut Notes) -> Result<()> {
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    // A scheme with a deprecated computation still verifies, because the lock pins its IDs, but
    // the lock should move to the replacement scheme (docs/DESIGN.md §3.1). A write of the lock
    // never adds a new ID of a deprecated scheme.
    for scheme in
        locked.iter().flat_map(|ids| ids.keys()).filter(|s| Scheme::from_name(s).is_some_and(Scheme::is_deprecated))
    {
        notes.warn(format_args!(
            "the {scheme} identity of '{}' uses a deprecated computation; migrate to its replacement (docs/DESIGN.md §3.1)",
            t.object_name
        ));
    }
    // Only a scheme that both the run and the lock have can show that the material is the same.
    // So the run never adds IDs to an object when none of them can be compared with an ID that
    // the lock already records (for example, a spec that computes only `cmac` for an object that
    // is locked only by `kw`).
    if let Some(ids) = locked.filter(|ids| !ids.is_empty())
        && !r.ids.keys().any(|s| ids.contains_key(s))
    {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockSharedScheme,
            format!(
                "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
             material; lock a spec that computes both first",
                t,
                r.ids.keys().collect::<Vec<_>>(),
                t.object_name,
                ids.keys().collect::<Vec<_>>()
            ),
        )));
    }
    let mut matched = false;
    let mut unlocked = Vec::new();
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => matched = true,
            Some(want) => {
                return Err(KmError::HashMismatch {
                    what: t.to_string(),
                    expected: want.clone(),
                    got: got.clone(),
                    check: Check::IdentityMaterial,
                });
            }
            // `record` adds this ID to the lock later, unless its scheme is deprecated.
            None if update => {}
            None => unlocked.push((scheme, got)),
        }
    }
    // A scheme that the lock does not record yet (for example, one that a newer cakeys computes)
    // is accepted when another scheme matched. When no scheme matched, the run is a first use. It
    // fails with `FirstUse`, which reports the computed ID, as a Nix fixed-output derivation
    // reports the hash that it got.
    if let Some((_, got)) = unlocked.first().filter(|_| !matched) {
        return Err(KmError::FirstUse { what: t.to_string(), got: (*got).clone() });
    }
    // The material matches, but the lock does not record that this spec is realised on this
    // token. The lock records where each object is, not only what it is, so the comparison fails.
    if !update && lock.realisation(t.spec_name, t.token_name).is_none() {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::LockRealised,
            format!(
                "{} matches the locked identity, but the lock records no realisation of spec '{}' on \
             token '{}'; review, then `lock`",
                t, t.spec_name, t.token_name
            ),
        )));
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
    // These locked schemes were not checked by this run. Either this version of cakeys does not
    // know them (for example, a newer version recorded them), or they cannot be computed for this
    // spec on this token.
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

/// Adds to the object's lock entry what it does not record yet: the object type (or a missing
/// `modulusBits` value), the commitment label, the IDs that `r` computed (except an ID of a
/// deprecated scheme), and the public key of a transport key. Returns whether the entry changed.
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
    // A label that the lock records is never replaced, because the IDs in the lock were computed
    // with it and every run computes with it (`commitment_label`). The label is added only when
    // the entry has none.
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
    // The public key of a transport key is recorded so that an export can read it from the lock
    // alone. The SPKI hashes to the `rfc7093m4` ID that was just compared, and the check on load
    // requires that a recorded public key matches that ID. So the key is added only when the
    // entry has none.
    if let Some(spki) = &r.public_key
        && entry.public_key.is_none()
    {
        use base64::Engine as _;
        entry.public_key = Some(base64::engine::general_purpose::STANDARD.encode(spki));
        changed = true;
    }
    changed
}

/// Records `r` in the lock: the object type, the commitment label and the IDs that the object
/// entry does not have yet, this realisation, and the pairs. It never overwrites an ID. Returns
/// whether the lock changed.
///
/// A realisation that the lock already records is replaced. Each difference that `compare` would
/// have refused without the write is reported on its own line. A person reviews the lock's diff,
/// so every change in the lock must be reported. A change in keys.toml is reported as a note. A
/// change on the token, which nobody edited in a file, is reported as a warning.
fn record(t: &Target, r: &Resolved, lock: &mut Lock, facts: &Facts, notes: &mut Notes) -> Result<bool> {
    let mut changed = false;
    // The lock holds one object per material within a class, and the check on load enforces this
    // again. So the run refuses to record the same material under a second object name. Two
    // certificates may share an `rfc7093m4` ID, because both can certify the same key.
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
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::LockOneName,
                format!("{t} is the same material as object '{name}' ({s}); use that object instead of a second name"),
            )));
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
        // The object's history is the import's `origin` for an import. Otherwise, it is what the
        // lock recorded for this same object. When the spec now points at another object, that
        // object has a different history, so nothing is kept.
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
        // When the spec now points at another object, its attributes differ from the old object's
        // attributes because it is a different object. That is not a change on the token, so no
        // warning is printed.
        for d in object_diff(r, prev).into_iter().filter(|_| prev.object == t.object_name) {
            notes.warn(format_args!("re-recorded {t}: {d} (changed on the token)"));
        }
        for (n, now) in r.policy.iter().filter(|(n, _)| !prev.policy.contains_key(*n)) {
            notes.note(format_args!("re-recorded {t}: {n} {now}, which the lock did not record"));
        }
    }
    // The load does not compute the keys of the observations again, so an entry under this key
    // may have been edited by hand. What this run saw replaces that entry, except for the
    // capability answers that earlier runs and the probe recorded. Those answers are kept next
    // to this run's answers, and this run's answer wins when both have the same key.
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
    // The pairs among the objects of this lock file are computed again. A listed pair that names
    // an object in another lock fragment is kept.
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

/// Reports how `observed` and the observation of this run differ from what the lock recorded.
/// These differences never change the result, because the CA-IDs enforce the identity, so a
/// different module build or a different token only produces a warning. `lock` records the new
/// values.
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

/// Compares the module that the lock recorded with the module of this run. A different module
/// build produces a warning, a different file of the same build produces a note, and the same
/// file with different content (the file was replaced in place) produces a warning.
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
        // The file has the same path but different content, so it was replaced in place. For a
        // path outside the Nix store, only the hash shows this, because the path does not change
        // with the content.
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

    /// A first use fails with `FirstUse` (18) when the run only compares. Recording fills the
    /// lock, and afterwards the same realisation compares without an error and records nothing
    /// new.
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

    /// A changed spec and a changed policy, which a write exists to record, fail only a compare. A
    /// downgrade, a replaced object and a hash mismatch fail a write too. An attestation change
    /// also fails a write; `attestation_changes_are_never_rerecorded` tests it.
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

    /// A write reports each change that it accepts. A changed spec produces a note, a policy
    /// attribute that changed on the token produces a warning, and a policy attribute that the
    /// lock did not record produces a note. A write of an unchanged realisation reports nothing.
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

    /// A pinned attestation is compared even when the run writes the lock. A different anchor
    /// means a different device (exit 14), a different ID under the same anchor means a changed
    /// object (exit 10), and a missing attestation is a downgrade (exit 14).
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

    /// A second spec of the same token object (with the same locator) cannot record the object
    /// with less than the first spec established, even when the run writes the lock. Here, less
    /// means without the attestation, or with the `token-asserted` binding. A second spec that is
    /// as strong as the first one is recorded. A spec with a different locator realises a
    /// different object with the same material, and that object may differ (review 2026-11-23
    /// A-2).
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
        crate::testing::assert_fires(&unattested, Check::LockSameObject);
        let asserted = record(&s2, &Resolved { binding: Some(Binding::TokenAsserted), ..attested(&s2) }).unwrap_err();
        assert!(matches!(&asserted, KmError::PreconditionFailed(m) if m.contains("binding downgrade")), "{asserted}");
        crate::testing::assert_fires(&asserted, Check::LockSameObject);
        record(&s2, &attested(&s2)).unwrap();
        record(&copy, &Resolved { binding: Some(Binding::TokenAsserted), ..plain(&copy) }).unwrap();
    }

    /// Provenance never changes the result: a different module build only adds a warning to the
    /// notes.
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

    /// An import records where the material came from (docs/CAMIGRATE.md D7). A later `lock` of
    /// the same object without an import keeps that origin, and the lock still loads.
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
        // An import is never a first use. Without the IDs that the lock recorded for the source,
        // nothing would check the material.
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

    /// The lock holds one entry per distinct observation (review A3). When a run records the
    /// realisation again under another module build, the realisation names a new entry, and the
    /// run drops the old entry because no realisation names it any more. The object's history
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
        // When an entry was edited by hand under its key, the run replaces it with what it saw.
        lock.observations.get_mut(&second).unwrap().mechanisms.clear();
        assert!(
            reconcile(&t, &resolved(&t), &mut lock, &facts("2"), LockWrite::Record, &mut Notes::default()).unwrap()
        );
        assert_eq!(lock.observations[&second], facts("2").observation);
    }

    /// The token's capability answers accumulate under one observation entry. The answers are not
    /// part of the entry's key, and a run that records answers keeps the answers that earlier runs
    /// recorded. When both have an answer for the same capability, the later run's answer wins.
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
        // A run that records no answers keeps the existing answers and does not change the lock.
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

    /// The hash of the module file: different content at the same path produces a warning,
    /// because the file was replaced in place, and for a path outside the Nix store only the hash
    /// shows that. A different path produces a note, as after a Nix rebuild.
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

    /// A compare reports these differences without failing: an attestation that the lock does
    /// not record yet (a note, because `lock` adds it), and three warnings: a public session where
    /// the realisation was made in a user session, mechanisms that the token no longer offers,
    /// and observation keys from a newer cakeys. A type that changed since the object was locked
    /// fails, whether the run writes the lock or not.
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

    /// A `modulusBits` value that keys.toml declares after the lock recorded the type describes the
    /// same key. A compare fails because the spec changed, and `lock` then records the size. A
    /// declared size that differs from the recorded size is still a different type (review
    /// 2026-11-23 A-5).
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

    /// A second run on the same realisation, or on a stronger one, passes whether it writes the
    /// lock or not. Here, the stronger realisation has the same attestation or a stronger mode. A
    /// weaker mode is a downgrade (exit 14). When the run only compares, it notes what the lock
    /// does not record yet. A write records it without the note.
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

    /// Pointing a spec at another object is a change in keys.toml. It fails with exit 14 when the
    /// run only compares, and a write records it again with a note. The lock's record of the old
    /// object is not compared with the new object. So a new object that was imported where the
    /// old one was generated, that has no attestation where the old one had one, and that has a
    /// weaker binding is neither a downgrade nor a change on the token. Earlier, the run reported
    /// all three, and `lock` refused to point the spec at the new object until someone edited
    /// the lock by hand.
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

    /// Every later run uses the commitment label that the lock's object entry records. Before the
    /// lock records one, runs use the default label. The lock writes the label only once. The
    /// test also checks that a line added with `Notes::say` appears in `Notes::lines`.
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

    /// Returns a keys.toml configuration with a second private key and two certificates in
    /// addition to `k`. Each object has a spec of the same name on the token `t`.
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

    /// When a run records, the lock holds one object per material within a class. The same key
    /// under a second name is refused (exit 14), and so is the same certificate. A key and its
    /// certificates share the public key, can be recorded in either order, and are listed as each
    /// other's pairs. A pair from another lock fragment is kept, and a pair in this file that
    /// shares no key is dropped.
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

    /// When a run compares, a note names the objects in this file that share the key and are not
    /// listed as pairs. A write lists them as pairs instead.
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
