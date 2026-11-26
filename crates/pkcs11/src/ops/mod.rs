//! The verbs `resolve`, `check`, `lock`, `create` and `delete`. Each verb is idempotent, and each
//! one follows the semantics of an HTTP method over two stores, the token and the lock, as
//! docs/CAKEYS.md describes.

use crate::provider::{Provider, Topic};
use crate::registry::Registry;
use crate::token::{self as hal, Token};
use cakeys_core::config::{
    Answered, AttestationRecord, Config, KeyOrigin, Lock, Mode, Observation, Observed, Origin, Session,
};
use cakeys_core::id::{self, Commit, HmacHash, Scheme};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError, Reason, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};

pub use cakeys_core::plan::{Target, binding, plan_mode};
use cakeys_core::plan::{block_commits, declared_commits};
use cakeys_core::reconcile::{self, commitment_label};
pub use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved};

mod capabilities;
mod identity;
mod planner;
mod rules;
pub use capabilities::*;
pub use identity::*;
pub use planner::*;
pub use rules::*;

/// Returns the attestation scheme that the token of `t` computes when the spec's token entry
/// opts in with `attestation = true`. Returns `None` when the entry does not opt in, or when the
/// token's provider does not attest objects of this class (§3.7 of docs/DESIGN.md).
fn attestation_scheme(t: &Target, tok: &Token) -> Option<Scheme> {
    t.on_token.attestation.then(|| tok.attestation_cap(&t.object)).flatten().map(|c| c.scheme)
}

/// Returns the commitments that a secret key's spec allows, without regard to what the token
/// implements. In `Mode::Commitment`, these are the commitments that the spec declares. In
/// `Mode::WrapRebind`, these are all the commitments for the key type. In every other mode, the
/// list is empty.
fn wanted_commits(t: &Target, mode: Mode) -> Vec<Commit> {
    match (mode, t.object.key_type) {
        (Mode::Commitment, _) => declared_commits(t),
        (Mode::WrapRebind, kt) => match kt.and_then(block_commits) {
            Some(all) => all.to_vec(),
            None => kt.and_then(HmacHash::for_key_type).map(Commit::Hmac).into_iter().collect(),
        },
        _ => vec![],
    }
}

/// Returns the commitments to compute for a secret key on this token. These are the commitments
/// from `wanted_commits` whose mechanism the token implements. Returns an `Unsupported` error
/// when the token implements none of them.
fn commits(t: &Target, tok: &Token, mode: Mode) -> Result<Vec<Commit>> {
    let wanted = wanted_commits(t, mode);
    if wanted.is_empty() {
        return Ok(vec![]);
    }
    let usable: Vec<Commit> = wanted.iter().copied().filter(|c| tok.has(hal::commit_mechanism(*c))).collect();
    if usable.is_empty() {
        let mechs: Vec<String> = wanted.iter().map(|c| hal::commit_mechanism(*c).to_string()).collect();
        return Err(tok.unsupported_for(
            Topic::Mechanism,
            format!("token '{}' implements none of {} needed for mode '{mode}' of {}", tok.name, mechs.join(", "), t),
        ));
    }
    Ok(usable)
}

/// Returns the schemes that this spec computes on this token. For a secret key, these are the
/// schemes of the commitments that the token implements. For every other class, these are the
/// schemes of `Target::schemes`. The list also includes the attestation scheme when the spec opts
/// in and the provider attests the class (§3.7). The function does not need the object, so a
/// caller can refuse a spec before anything is created.
///
/// # Errors
///
/// `Unsupported` if the token implements none of the spec's commitments, and the error of
/// `plan_mode` when `plan_mode` rejects the spec.
pub fn schemes_on(t: &Target, tok: &Token) -> Result<Vec<Scheme>> {
    let mut v = if t.object.class == Class::SecretKey {
        commits(t, tok, plan_mode(t)?)?.iter().map(|c| c.scheme()).collect()
    } else {
        t.schemes()
    };
    if let Some(s) = attestation_scheme(t, tok) {
        v.push(s);
    }
    Ok(v)
}

/// Says whether a run may create the device state that an attestation needs, which is a TPM
/// Attestation Key. Only the verbs that write (`lock` and `create`) use `IfMissing`. A verb that
/// only reads uses `Never`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Provision {
    Never,
    IfMissing,
}

/// The GET verb. It finds the object by its locator (the locator must match exactly one object),
/// checks the object's type and attributes, and computes the object's IDs. It never writes to the
/// lock or to the token. For that reason, a TPM Attestation Key that is not provisioned yet is an
/// error here, and only `lock` provisions it. Returns `None` when the locator finds no object.
///
/// # Errors
///
/// - `Unavailable` when the locator finds no object and the session cannot see private objects
///   (`needs_login`).
/// - `Ambiguous` when the locator finds several objects.
/// - `Conflict` for a wrong type or a wrong policy. For a private key, also `Conflict` when a
///   public key object under the locator holds another key.
/// - `Unsupported` or `Unavailable` when the object cannot be proven or attested as the spec
///   requires.
pub fn resolve(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Option<Resolved>> {
    resolve_with(t, tok, lock, Provision::Never, notes)
}

fn resolve_with(
    t: &Target,
    tok: &Token,
    lock: &Lock,
    provision: Provision,
    notes: &mut Notes,
) -> Result<Option<Resolved>> {
    let mode = plan_mode(t)?;
    let public_only = t.on_token.public_only;
    let Some(h) = tok.find_key(&t.object, &t.on_token.locator, public_only)? else {
        rules::needs_login(t, tok, lock, "it is not there")?;
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    if t.object.class.is_asymmetric() || t.object.class == Class::Certificate {
        tok.check_unique_private_id(h)?;
    }
    tok.check_public_half(h, t.spec, &t.on_token.locator, public_only)?;
    let Computed { ids, binding, commitment_label, spki, commits } = compute_ids(t, tok, lock, h, mode)?;
    // The key's public key is read once (review D8), so that every check below compares with the
    // same value that the identity hashed. For a key whose identity is not computed from its
    // public key, the closure reads the public key from the token when a check needs it.
    let spki = || spki.clone().map_or_else(|| tok.spki(h, &t.on_token.locator), Ok);
    // This check runs after the IDs are computed, so that a private key that was replaced by
    // another key reports its failed proof of possession first.
    if t.object.class == Class::PrivateKey && !public_only {
        tok.check_public_objects(&spki()?, &t.on_token.locator)?;
    }
    let attestation = match attestation_scheme(t, tok) {
        Some(scheme) => {
            let spki = if t.object.class.is_asymmetric() { Some(spki()?) } else { None };
            let committed = committed(t, &commits, commitment_label.as_deref(), &ids);
            Some(attest(t, tok, lock, h, spki.as_deref(), &committed, scheme, provision, notes)?)
        }
        None => None,
    };
    Ok(Some(Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: tok.uri(&t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(&t.object, t.spec),
        ids,
        binding,
        assurance: cakeys_core::plan::assurance(t.object.class, binding, attestation.as_ref().map(|a| a.kind.as_str())),
        policy: tok.policy(h)?,
        immutables: tok.immutables(h)?,
        commitment_label,
        attestation,
        public_key: if t.transport { Some(spki()?) } else { None },
    }))
}

/// What [`compute_ids`] establishes about an object.
struct Computed {
    ids: std::collections::BTreeMap<String, String>,
    /// The binding of a private key as the run observed it, not as the plan expected it. For
    /// example, a key with `CKA_ALWAYS_AUTHENTICATE` records the `pop-sign-pin` binding that it
    /// proved.
    binding: Option<cakeys_core::config::Binding>,
    /// The label that the commitments were computed with, or `None` when no commitment was
    /// computed.
    commitment_label: Option<String>,
    /// The key's canonical SPKI, when the identity is computed from it (an asymmetric key in
    /// `Mode::Direct`).
    spki: Option<Vec<u8>>,
    /// The commitments that were computed for a secret key, with `commitment_label` as the label.
    commits: Vec<Commit>,
}

/// Returns each commitment in `commits` that was computed with `label`, together with its input
/// and the ID that it produced (taken from `ids`). A secret key's attestation is bound to these
/// commitments (review 2026-11-23 B-1). Returns an empty list when `label` is `None`.
fn committed(
    t: &Target,
    commits: &[Commit],
    label: Option<&str>,
    ids: &std::collections::BTreeMap<String, String>,
) -> Vec<crate::provider::Commitment> {
    let Some(label) = label else { return Vec::new() };
    commits
        .iter()
        .filter_map(|c| {
            let id = ids.get(c.scheme().name())?.clone();
            Some(crate::provider::Commitment { commit: *c, input: c.input(label, &t.object), id })
        })
        .collect()
}

/// Computes the material IDs of the object `h` of `t` on `tok` in `mode`. Both `resolve` and
/// `delete` (for If-Match) compute the IDs with this function. For a private key, the computation
/// also proves possession of the key.
fn compute_ids(t: &Target, tok: &Token, lock: &Lock, h: ObjectHandle, mode: Mode) -> Result<Computed> {
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    let binding = tok.recorded_binding(h, binding(t))?;
    let spki = match mode {
        Mode::Direct if t.object.class.is_asymmetric() => Some(tok.spki(h, &t.on_token.locator)?),
        _ => None,
    };
    let ids = tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label, binding, spki.as_deref())?;
    Ok(Computed { ids, binding, commitment_label: (!commits.is_empty()).then_some(label), spki, commits })
}

/// Computes the attestation record (§3.7), which is a per-device identity derived from signed
/// provenance. The material SPKI that the attestation must name is the same SPKI that the
/// `rfc7093m4` scheme hashed. An attestation of other material is therefore a conflict, and it is
/// never accepted as an additional identity.
///
/// When the lock already records an attestation for this realisation, a run that cannot attest
/// (because the TPM is unreachable, no PIN is available, or there is no attestation certificate)
/// is a scheme downgrade and fails with exit 14. This is the same result as when a realisation
/// stops computing any other scheme. A conflict (exit 13) and an ambiguity (exit 12) keep their
/// own codes, because they mean that the evidence is wrong, not that it is missing.
#[expect(clippy::too_many_arguments, reason = "one caller, `resolve_with`, which holds them all")]
fn attest(
    t: &Target,
    tok: &Token,
    lock: &Lock,
    h: ObjectHandle,
    spki: Option<&[u8]>,
    commitments: &[crate::provider::Commitment],
    scheme: Scheme,
    provision: Provision,
    notes: &mut Notes,
) -> Result<AttestationRecord> {
    let kind = scheme.attestation_kind().ok_or_else(|| {
        KmError::Unsupported(
            format!("provider '{}' advertises unknown attestation scheme {scheme}", tok.provider.name()).into(),
        )
    })?;
    let a = match tok.attest(h, &t.object, spki, commitments, provision == Provision::IfMissing) {
        Ok(a) => a,
        Err(e @ (KmError::Unavailable(_) | KmError::Unsupported(_) | KmError::NotFound(_))) => {
            let locked = lock.realisation(t.spec_name, t.token_name).and_then(|r| r.attestation.as_ref());
            return Err(match locked {
                Some(was) => KmError::PreconditionFailed(Reason::check(
                    Check::LockAttestationKept,
                    format!(
                        "identity downgrade for {}: it was realised with a {} attestation, which it cannot compute now: {e}",
                        t, was.kind
                    ),
                )),
                None => e,
            });
        }
        Err(e) => return Err(e),
    };
    if a.scheme != scheme {
        return Err(KmError::Conflict(Reason::check(
            Check::AttestScheme,
            format!("provider '{}' advertises {scheme} but attested {}", tok.provider.name(), a.scheme),
        )));
    }
    if let Some(w) = &a.warning {
        notes.warn(format!("{t}: its attestation would fail `check` today: {w}"));
    }
    if let Some(c) = &a.caveat {
        notes.warn(format!("{t}: {c}"));
    }
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// Says what a run did with its key, for [`answers`]. `Found` means that the run found the key
/// under its locator. `Created` means that the run created the key, and it holds the module's
/// note when the module made the key differently from how it was asked.
#[derive(Clone, Copy)]
enum Run<'a> {
    Found,
    Created(Option<&'a hal::CreateNote>),
}

/// Returns what the run of `t` on its token demonstrated, as capability rows (docs/CAPROBE.md).
/// The rows are the proof of possession that the run gave and, when the run created the key, the
/// key generation. The generation row has `via = "by-name"` when the module accepted the curve
/// only by its name (ISSUES.md B18). A run that failed records nothing, so every row here has the
/// answer yes.
fn answers(t: &Target, r: &Resolved, run: Run<'_>) -> std::collections::BTreeMap<String, Answered> {
    let mut out = std::collections::BTreeMap::new();
    if !t.object.class.is_asymmetric() {
        return out;
    }
    // The row keys are the names of `cakeys_profile::Capability`, because the gate reads the rows
    // back by those names.
    if let Some(proof) = r.binding.and_then(|b| rules::proof_capability(&t.object, b)) {
        out.insert(proof.to_string(), Answered::yes());
    }
    if let Run::Created(note) = run
        && let Some(generated) = rules::generate_capability(&t.object)
    {
        let via = note.and_then(|n| n.by_name.as_ref()).map(|_| "by-name".to_owned());
        out.insert(generated.to_string(), Answered { via, ..Answered::yes() });
    }
    out
}

/// Returns what this run observes of `tok` (the session, the mechanisms, the profile, the module
/// and the token) and what the run of `t` demonstrated ([`answers`]). The lock records these facts
/// or compares them with the facts that it already holds.
fn facts(t: &Target, tok: &Token, r: &Resolved, run: Run<'_>) -> Facts {
    Facts {
        observed: Observed { uri: r.uri.clone(), session: if tok.logged_in { Session::User } else { Session::Public } },
        observation: Observation {
            provider: Some(tok.provider.name().to_owned()),
            cakeys_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            profile: tok.profiles.module_name().map(str::to_owned),
            mechanisms: tok.mechanism_names(),
            module: Some(tok.module.clone()),
            token: Some(tok.token.clone()),
            capabilities: answers(t, r, run),
            extra: std::collections::BTreeMap::new(),
        },
        origin: None,
    }
}

/// The GET verb with If-Match against the lock. It resolves the object and compares the result
/// with the lock. It never writes to the lock or to the token.
///
/// # Errors
///
/// - Every error of `resolve`.
/// - `NotFound` when `resolve` finds nothing. The message names the command that puts the object
///   there, such as `cakeys create`.
/// - Every rejection of `compare`: `HashMismatch` (exit 10) when the token's IDs differ from the
///   IDs in the lock, `FirstUse` (exit 18) when the lock records no ID to compare with, and
///   `PreconditionFailed` (exit 14) for a realisation that moved.
pub fn verify(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Resolved> {
    let r = resolve(t, tok, lock, notes)?.ok_or_else(|| absent(t))?;
    reconcile::compare(t, &r, lock, &facts(t, tok, &r, Run::Found), LockWrite::Compare, notes)?;
    Ok(r)
}

/// The `lock` verb. It finds the object, compares it with the lock, and records what the lock
/// does not hold yet or what changed in the facts that the lock records about the realisation
/// (docs/CAKEYS.md). It never creates the object, because only `create` does that. It does
/// provision a TPM Attestation Key when the realisation needs one.
///
/// # Errors
///
/// - `Validation` or `Unsupported` when `plan_mode` or `check_capabilities` rejects the pair,
///   before the object is looked for.
/// - `NotFound` when the locator finds nothing.
/// - Every error that `resolve` returns for the object that it found.
/// - Every rejection of `compare` for the realised object.
pub fn lock(t: &Target, tok: &Token, lock: &mut Lock, write: LockWrite, notes: &mut Notes) -> Result<(Resolved, bool)> {
    lock_as(t, tok, lock, write, None, notes)
}

/// Records an object that camigrate has just imported (docs/CAMIGRATE.md D6, D7). It works as
/// [`lock`] does and applies the same lock rules, and it also sets the realisation's
/// `provenance.origin` to the place that the material came from. The lock must already record
/// the object's IDs, because camigrate copied them from the source. Different material is
/// therefore a hash mismatch (exit 10) and never a new identity.
///
/// # Errors
///
/// - `NotFound` when the object is not under the locator.
/// - Every refusal of [`lock`] for an object that it found, including a hash mismatch (exit 10).
/// - `PreconditionFailed` when the lock records no ID for the object, because `reconcile` refuses
///   an import that would be a first use.
pub fn lock_import(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    origin: Origin,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    lock_as(t, tok, lock, LockWrite::Record, Some(origin), notes)
}

/// The shared implementation of [`lock`] and [`lock_import`]. `origin` is `Some` only for an
/// import, and the lock then records where the imported material came from.
fn lock_as(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    write: LockWrite,
    origin: Option<Origin>,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode, Verb::Lock)?;
    let r = resolve_with(t, tok, lock, Provision::IfMissing, notes)?.ok_or_else(|| absent(t))?;
    let facts = Facts { origin, ..facts(t, tok, &r, Run::Found) };
    let changed = reconcile::reconcile(t, &r, lock, &facts, write, notes)?;
    Ok((r, changed))
}

/// Returns the `NotFound` error for the object of `t` when the object is not under its locator.
/// The message names the command that puts the object there, which depends on the `origin` of the
/// pair.
fn absent(t: &Target) -> KmError {
    let what = match t.on_token.key_origin() {
        KeyOrigin::Create => "`cakeys create` makes it".to_owned(),
        KeyOrigin::Import => format!("camigrate brings it (camigrate migrate {} --to {})", t.object_name, t.token_name),
        KeyOrigin::File => {
            format!("camigrate brings it from its file (camigrate import {} --to {})", t.object_name, t.token_name)
        }
        KeyOrigin::Adopt => "it is adopted, and nothing cakeys runs puts it there".to_owned(),
    };
    KmError::NotFound(format!("{t}: not under its locator; {what}").into())
}

/// Creates the object of `t`, which `resolve` did not find, and then resolves it. [`create`]
/// calls this function only after [`token_rules`] found nothing to refuse, so those refusals
/// happen before anything is created. When the identity of the created object cannot be
/// established, the function removes the object again. Returns the resolved object and, when the
/// module made the key differently from how it was asked, the module's note.
fn create_absent(
    t: &Target,
    tok: &Token,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(Resolved, Option<hal::CreateNote>)> {
    let made_otherwise = match tok.create(t.object, t.spec, &t.on_token.locator, cakeys_core::plan::expected_binding(t))
    {
        Ok(made) => made,
        // A module may return an error after it made the key, for example an error after the
        // write, or an error while the session is restored after a step as the SO. The locator
        // was empty before, so whatever is under the locator now was made by this creation.
        Err(e) => return Err(undo_created(t, tok, e, "the creation failed", notes)),
    };
    notes.say(format!("created {t}"));
    if let Some(note) = &made_otherwise {
        notes.say(note.to_string());
    }
    let e = match resolve_with(t, tok, lock, Provision::IfMissing, notes) {
        Ok(Some(r)) => return Ok((r, made_otherwise)),
        Ok(None) => KmError::NotFound(format!("{t} vanished after creation").into()),
        Err(e) => e,
    };
    Err(undo_created(t, tok, e, "its identity could not be established", notes))
}

/// Removes what is under the locator of `t` after a creation there failed for the reason `why`.
/// Only [`create_absent`] calls this function, for two failures: the module's creation call
/// failed, or the identity of the created object could not be established. The locator was empty
/// before the creation (If-None-Match), so this function removes only what the creation made, and
/// a failed creation leaves nothing behind. The exception is a module that cannot delete keys
/// (ykcs11): the note then says that the key is still on the token instead of saying that it was
/// removed. Returns `err` unchanged.
fn undo_created(t: &Target, tok: &Token, err: KmError, why: &str, notes: &mut Notes) -> KmError {
    match tok.find_any(&t.on_token.locator) {
        Ok(found) if found.is_empty() => {}
        Ok(_) => match tok.destroy(&t.object, &t.on_token.locator) {
            Ok(n) => notes.say(format!("removed {n} object(s) just created for {t}: {why}")),
            Err(d) => notes.say(format!(
                "the key just created for {t} is still on the token ({why}, and removing it failed: {d})"
            )),
        },
        Err(f) => notes.say(format!(
            "{t}: {why}, and what it may have left under the locator cannot be seen ({f}); look before creating it \
             again"
        )),
    }
    err
}

/// Says what [`create`] did with its pair.
#[derive(Debug)]
pub enum Made {
    /// The key was created and recorded. The `bool` says whether the lock changed.
    Created(Resolved, bool),
    /// The key was already under the locator, and the lock records its IDs. The key was verified
    /// as `check` verifies it, and nothing was created or written.
    Verified(Resolved),
}

/// The PUT verb with If-None-Match. It creates the object under the declared locator and then
/// records it as [`lock`] does. It is the only verb that creates an object, and it creates one
/// only for a pair whose `origin` is `create`.
///
/// When the lock records the object's IDs and a key is already under the locator, the function
/// verifies the key as `check` does ([`verify`]) and leaves it alone. When the lock does not
/// record the object and a key is already under the locator, the result is `Exists` (exit 19),
/// whatever the key holds. That refusal comes before any capability of the token is checked,
/// because `lock` is the verb for a key that is already there. Every other guard of a creation
/// also applies: the lock must not already record the object's material (D1), and no object of
/// another class may be under the locator.
///
/// # Errors
///
/// - `Validation` (exit 17) for a pair whose origin is not `create`, before the token is used.
/// - The errors of [`verify`] for a key that the lock records and that is already there:
///   `HashMismatch` (exit 10) for other material, and `PreconditionFailed` (exit 14) for a
///   realisation that the lock does not record or that moved.
/// - `Exists` (exit 19) when a key that the lock does not record is already under the locator,
///   and `Ambiguous` when several keys are there.
/// - The rejections of `plan_mode` and `check_capabilities`, including a rejection of the key
///   generation.
/// - `PreconditionFailed` (D1) when the lock records the object's material and the token lost
///   the object.
/// - `Unavailable` when a session without login cannot see the objects under the locator.
/// - `Conflict` when an object of another class is under the locator.
/// - The rejections of `compare` for the object just created.
pub fn create(t: &Target, tok: &Token, lock: &mut Lock, write: LockWrite, notes: &mut Notes) -> Result<Made> {
    plan_mode(t)?;
    if let Some(why) = not_origin_create(t) {
        return Err(KmError::Validation(format!("{t}: {why}").into()));
    }
    if pinned(t, lock).is_some() && tok.find_key(&t.object, &t.on_token.locator, false)?.is_some() {
        let r = verify(t, tok, lock, notes)?;
        notes.say(format!("{t} is already there and matches the lock: nothing created"));
        return Ok(Made::Verified(r));
    }
    // Check the token's rules, which `create --dry-run` also checks, again now, just before the
    // write.
    if let Some(r) = token_rules(t, tok, lock, Verb::Create)?.into_iter().next() {
        return Err(r.into());
    }
    let (r, note) = create_absent(t, tok, lock, notes)?;
    let changed = reconcile::reconcile(t, &r, lock, &facts(t, tok, &r, Run::Created(note.as_ref())), write, notes)?;
    Ok(Made::Created(r, changed))
}

/// Says what [`delete`] did with the object under the locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deleted {
    /// It held the expected identity and was destroyed.
    Deleted,
    /// It holds the expected identity, so a run without `dry_run` would destroy it.
    WouldDelete,
    /// Nothing is under the locator.
    Absent,
}

impl Deleted {
    /// Returns the name of this outcome in the output of `cakeys delete`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Deleted::Deleted => "deleted",
            Deleted::WouldDelete => "would-delete",
            Deleted::Absent => "absent",
        }
    }
}

/// The DELETE verb with If-Match. An absent object counts as success. The function removes only
/// the identified object, and also a private key's public half when the public half holds the
/// same key. It leaves everything else under the locator alone. It then removes the realisation
/// from the lock, but it keeps the object's `ids`, because the material may still exist on other
/// tokens. With `dry_run`, the function identifies the object and checks If-Match as a delete
/// does, and it changes nothing. Returns what the function did and whether it changed the lock.
///
/// # Errors
///
/// - `Unsupported` for an object adopted with `publicOnly`, or when no identity can be computed
///   for the If-Match check.
/// - `Unavailable` when a session without login finds no private object, because such a session
///   cannot see private objects.
/// - `PreconditionFailed` when there is no expected ID to check against (no `--if-match` and no
///   ID in the lock), or when the token holds an ID other than the expected one.
/// - `Unsupported` (exit 15, `delete-refused`), also for a dry run, when the module's profile or
///   the provider says that the module does not remove the object.
/// - `Unavailable` (exit 16, `delete-kept`) when a destroyed object is still under the locator.
///
/// A refusal leaves the lock unchanged.
pub fn delete(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    if_match: Option<&str>,
    dry_run: bool,
    notes: &mut Notes,
) -> Result<(Deleted, bool)> {
    if t.on_token.public_only {
        return Err(KmError::Unsupported(
            format!("{t} is adopted publicOnly; deleting would remove only the public half").into(),
        ));
    }
    let loc = &t.on_token.locator;
    // An expected identity is only required when there is something to delete.
    let mut outcome = Deleted::Absent;
    if let Some(h) = tok.find_key(&t.object, loc, false)? {
        // Refuse when the module would not remove the object. A dry run refuses in the same way
        // as the delete.
        rules::delete_refused(t, tok)?;
        // The IDs are computed as `resolve` computes them, including the proof of possession, so
        // that If-Match cannot pass because of a public key object that holds the expected key
        // next to a private key that holds another key.
        let Computed { ids: got, spki, .. } = compute_ids(t, tok, lock, h, plan_mode(t)?)?;
        // The schemes that were computed, in the spec's order of preference. The first one is the
        // primary scheme.
        let computed: Vec<Scheme> = t.schemes().into_iter().filter(|s| got.contains_key(s.name())).collect();
        let primary =
            *computed.first().ok_or_else(|| KmError::Unsupported(format!("no identity computed for {t}").into()))?;
        // The value of `--if-match` is an ID of the primary scheme. Without `--if-match`, the
        // expected ID is the lock's ID for the first computed scheme that the lock records.
        let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
        let (scheme, expected) = match if_match {
            Some(want) => (primary, want.to_owned()),
            None => computed.iter().find_map(|s| Some((*s, locked?.get(s.name())?.clone()))).ok_or_else(|| {
                let e = KmError::PreconditionFailed(Reason::rule(
                    Rule::IfMatch,
                    format!("no expected {primary} for {t}; pass --if-match"),
                ));
                KmError::from(Refusal::new(Rule::IfMatch, e))
            })?,
        };
        if got.get(scheme.name()) != Some(&expected) {
            let e = KmError::PreconditionFailed(Reason::rule(
                Rule::IfMatch,
                format!("{} holds {:?}, expected {expected}; not deleting", t, got.get(scheme.name())),
            ));
            return Err(Refusal::new(Rule::IfMatch, e).into());
        }
        if dry_run {
            notes.say(format!("{t} holds {expected}: a delete would destroy it"));
            return Ok((Deleted::WouldDelete, false));
        }
        let (n, left) = tok.destroy_identified(h, &t.object, loc, spki.as_deref())?;
        outcome = Deleted::Deleted;
        notes.say(format!("destroyed {n} object(s) for {t}"));
        if left > 0 {
            notes
                .note(format_args!("left {left} public key object(s) under the locator of {t}: they hold another key"));
        }
    } else {
        rules::needs_login(t, tok, lock, "it is absent")?;
    }
    let mut changed = false;
    if !dry_run && let Some(m) = lock.realisations.get_mut(t.spec_name) {
        changed = m.remove(t.token_name).is_some();
        if m.is_empty() {
            lock.realisations.remove(t.spec_name);
        }
        changed |= lock.drop_unreferenced_observations();
    }
    Ok((outcome, changed))
}

/// Splits a `check` reference into the object name and, for a reference of the form
/// `<object>.id.<scheme>`, the scheme name.
#[must_use]
pub fn split_reference(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once(".id.") {
        Some((object, scheme)) => (object, Some(scheme)),
        None => (reference, None),
    }
}

/// The pseudo-FOD check before use. `reference` has the form `<object>` or
/// `<object>.id.<scheme>`, and it is `None` when `spec` selects the pair. The function selects the
/// (spec, token) pair and checks it with [`verify`] in a read-only session. `open` opens the
/// token.
///
/// The function never writes to the lock, to the token, or to a TPM's persistent handles. An
/// object that is not there is `NotFound`, and the message names the command that makes it, such
/// as `cakeys create`. An object that is there but whose ID the lock does not record fails with
/// its `got:` (`FirstUse`, exit 18). A requested scheme must be one that the spec computes on this
/// token; otherwise it is refused (exit 15) before the token is opened or before the object is
/// looked for. The lock must also record the requested scheme itself. It is not enough that the
/// scheme was computed while another scheme matched: that case is a first use of the scheme
/// (exit 18), and the message shows its `got:`.
///
/// # Errors
///
/// - `Unsupported` (exit 15) for a scheme that the spec does not compute on this token.
/// - `FirstUse` (exit 18) when a requested scheme is computed but the lock does not record it.
///   Its `got:` shows the computed ID.
/// - The errors of `Config::address`, `Target::new` and `verify`: the reference and the pair must
///   exist, and the realisation must match the lock.
pub fn check(
    cfg: &Config,
    reference: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
    open: impl FnOnce(&str, hal::Access) -> Result<Token>,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<Resolved> {
    check_open(cfg, reference, spec, token, open, lock, notes).map(|(r, _)| r)
}

/// Works as [`check`] does, and also returns the token that it opened. A caller uses the token to
/// read more of the verified object. For example, the CLI's key-file output reads the object's
/// `CKA_ID`.
///
/// # Errors
///
/// The same errors as [`check`].
pub fn check_open(
    cfg: &Config,
    reference: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
    open: impl FnOnce(&str, hal::Access) -> Result<Token>,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(Resolved, Token)> {
    let (object, requested) = reference.map_or((None, None), |r| {
        let (object, scheme) = split_reference(r);
        (Some(object), scheme)
    });
    let (spec_name, token_name) = cfg.address(object, spec, token)?;
    let t = Target::new(cfg, &spec_name, &token_name)?;
    let object = t.object_name;
    // A scheme that the spec can never compute is refused before the token is opened.
    let scheme = requested.map(|name| requested_scheme(&t, name, None)).transpose()?;
    let tok = open(&token_name, hal::Access::Read)?;
    if let Some(w) = tok.pin_warning() {
        notes.warn(w);
    }
    // The token may lack a mechanism that the spec allows, so the scheme is checked again against
    // the token's schemes before the object is looked for.
    if let Some(s) = scheme {
        requested_scheme(&t, s.name(), Some(&schemes_on(&t, &tok)?))?;
    }
    let r = verify(&t, &tok, lock, notes)?;
    // The lock records an attestation on the realisation (§3.7), not on the object, so an
    // attestation scheme is looked up in the realisation.
    if let Some(s) = scheme {
        let (locked, got) = if s.is_attestation() {
            let locked = lock
                .realisation(&spec_name, &token_name)
                .and_then(|r| r.attestation.as_ref())
                .is_some_and(|a| Some(a.kind.as_str()) == s.attestation_kind());
            (locked, r.attestation.as_ref().map(|a| a.id.clone()))
        } else {
            (
                lock.objects.get(t.object_name).is_some_and(|o| o.ids.contains_key(s.name())),
                r.ids.get(s.name()).cloned(),
            )
        };
        if !locked {
            return Err(KmError::FirstUse { what: format!("'{object}' (scheme {s})"), got: got.unwrap_or_default() });
        }
    }
    Ok((r, tok))
}

/// Returns the scheme `name` that a reference of the form `<object>.id.<scheme>` requests of `t`.
/// Before the token is opened, `on_token` is `None`, and the allowed schemes are the spec's own
/// schemes and, when the spec opts in, any attestation scheme, because only the provider decides
/// which attestation scheme applies. After the token is opened, `on_token` holds the schemes that
/// the token computes ([`schemes_on`]). A refusal (exit 15) has the same wording in both cases,
/// so that the same mistake always gives the same message (ops F4).
///
/// # Errors
///
/// `Unsupported` for a scheme that the spec does not compute there, or for a name that is not a
/// scheme.
fn requested_scheme(t: &Target, name: &str, on_token: Option<&[Scheme]>) -> Result<Scheme> {
    let scheme = Scheme::from_input(name);
    let attests = t.on_token.attestation && on_token.is_none();
    let computes = on_token.map_or_else(|| t.schemes(), <[Scheme]>::to_vec);
    match scheme {
        Some(s) if computes.contains(&s) || (attests && s.is_attestation()) => Ok(s),
        _ => Err(KmError::Unsupported(
            format!(
                "scheme '{}' for spec '{}' on '{}'; it computes {:?}{}",
                scheme.map_or(name, |s| s.name()),
                t.spec_name,
                t.token_name,
                computes.iter().map(|s| s.name()).collect::<Vec<_>>(),
                if attests { " plus its token's attestation scheme" } else { "" }
            )
            .into(),
        )),
    }
}

/// One (spec, token) pair that [`check_token`] verified, and the result.
pub struct PairCheck {
    /// The spec that realises the object.
    pub spec: String,
    /// The object that the spec realises.
    pub object: String,
    /// The result of [`verify`] for this pair.
    pub result: Result<Resolved>,
}

/// Runs [`check`] on every (spec, token) pair that keys.toml places on `token`, in one read-only
/// session. A pair that fails does not stop the checks of the other pairs, and the function
/// returns the result of each pair. It never writes. `open` opens the token.
///
/// # Errors
///
/// `Validation` (exit 17) for a token that keys.toml does not name, or on which no spec places
/// an object. Every error of `open`. The failure of a single pair is in its [`PairCheck`] and is
/// never returned here.
pub fn check_token(
    cfg: &Config,
    token: &str,
    open: impl FnOnce(&str, hal::Access) -> Result<Token>,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(Vec<PairCheck>, Token)> {
    let pairs = cfg.select(None, None, Some(token))?;
    if pairs.is_empty() {
        return Err(KmError::Validation(format!("no spec places an object on token '{token}'").into()));
    }
    let tok = open(token, hal::Access::Read)?;
    if let Some(w) = tok.pin_warning() {
        notes.warn(w);
    }
    let checked = pairs
        .into_iter()
        .map(|(spec, _)| {
            let object = cfg.specs[spec].object.clone();
            let result = Target::new(cfg, spec, token).and_then(|t| verify(&t, &tok, lock, notes));
            PairCheck { spec: spec.to_owned(), object, result }
        })
        .collect();
    Ok((checked, tok))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scheme that a reference requests is refused with the same wording before the token is
    /// opened and after it is opened (ops F4). Before the open, the allowed schemes are the spec's
    /// schemes and, when the spec opts in, any attestation scheme. After the open, the allowed
    /// schemes are those that the token computes.
    #[test]
    fn a_requested_scheme_is_refused_alike_before_and_after_the_open() {
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\ntokens.t = { locator = { CKA_LABEL = \"k\" }, attestation = true }\n",
        )
        .unwrap();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let refused = |name: &str, on_token: Option<&[Scheme]>| match requested_scheme(&t, name, on_token) {
            Err(KmError::Unsupported(m)) => m.into_text(),
            other => panic!("{name}: {other:?}"),
        };
        assert_eq!(requested_scheme(&t, "rfc7093m4", None).unwrap(), Scheme::Rfc7093m4);
        assert_eq!(requested_scheme(&t, "piv-attestation", None).unwrap(), Scheme::PivAttestation);
        let before = refused("cmac", None);
        assert!(before.starts_with("scheme 'cmac' for spec 's' on 't'; it computes [\"rfc7093m4\""), "{before}");
        assert!(before.ends_with(" plus its token's attestation scheme"), "{before}");
        assert!(refused("nope", None).starts_with("scheme 'nope' for spec 's' on 't'; it computes"));
        let on_token = [Scheme::Rfc7093m4];
        assert_eq!(requested_scheme(&t, "rfc7093m4", Some(&on_token)).unwrap(), Scheme::Rfc7093m4);
        let after = refused("piv-attestation", Some(&on_token));
        assert_eq!(after, "scheme 'piv-attestation' for spec 's' on 't'; it computes [\"rfc7093m4\"]");
    }
}
