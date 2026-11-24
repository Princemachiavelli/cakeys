//! Idempotent verbs with HTTP-like semantics (docs/CAKEYS.md).

use crate::provider::{Provider, Registry};
use crate::token::{self as hal, Token};
use cakeys_core::config::{
    Answered, AttestationRecord, Config, KeyOrigin, Lock, Mode, Observation, Observed, Origin, Session,
};
use cakeys_core::id::{self, Commit, HmacHash, Scheme};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};

pub use cakeys_core::plan::{Target, binding, plan_mode};
use cakeys_core::plan::{block_commits, declared_commits};
use cakeys_core::reconcile::{self, commitment_label};
pub use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved};

mod capabilities;
mod planner;
pub use capabilities::*;
pub use planner::*;

/// The attestation scheme `t`'s token computes when opted in (`attestation = true`), if the
/// provider attests this class at all (§3.7 of docs/DESIGN.md).
fn attestation_scheme(t: &Target, tok: &Token) -> Option<Scheme> {
    t.on_token.attestation.then(|| tok.attestation_cap(t.object)).flatten().map(|c| c.scheme)
}

/// The commitments a secret key's spec allows (or, for a wrap-rebind copy, every one for the
/// key type), whatever the token: empty for every other mode.
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

/// Commitments to compute for a secret key on this token: those the spec allows (or, for a
/// wrap-rebind copy, every one for the key type) that the token implements.
fn commits(t: &Target, tok: &Token, mode: Mode) -> Result<Vec<Commit>> {
    let wanted = wanted_commits(t, mode);
    if wanted.is_empty() {
        return Ok(vec![]);
    }
    let usable: Vec<Commit> = wanted.iter().copied().filter(|c| tok.has(hal::commit_mechanism(*c))).collect();
    if usable.is_empty() {
        let mechs: Vec<String> = wanted.iter().map(|c| hal::commit_mechanism(*c).to_string()).collect();
        return Err(tok.unsupported(format!(
            "token '{}' implements none of {} needed for mode '{mode}' of {}",
            tok.name,
            mechs.join(", "),
            t
        )));
    }
    Ok(usable)
}

/// Schemes this spec computes on this token: `Target::schemes` narrowed to the commitments the
/// token implements, plus the attestation scheme when the spec opted in and the provider
/// attests the class (§3.7). Needs no object, so callers can refuse before anything is created.
///
/// # Errors
///
/// `Unsupported` if the token implements none of the spec's commitments (or `plan_mode`
/// rejects the spec).
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

/// Whether a run may create the device state an attestation needs (a TPM Attestation Key):
/// only the verbs that write (`lock`, `create`), never a read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Provision {
    Never,
    IfMissing,
}

/// The verb a capability check is for: `create` also needs the generation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Lock,
    Create,
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes,
/// neither the lock nor the token: a TPM Attestation Key that is not provisioned yet is an
/// error here, and only `lock` provisions it.
///
/// # Errors
///
/// `NotFound` when the locator finds no object, `Ambiguous` when it finds several; `Conflict`
/// for a wrong type or policy, or — for a private key — a public key object under the locator
/// that holds another key; `Unsupported`/`Unavailable` when the object cannot be proven or
/// attested as the spec requires.
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
    let Some(h) = tok.find_key(t.object, &t.on_token.locator, public_only)? else {
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    if t.object.class.is_asymmetric() || t.object.class == Class::Certificate {
        tok.check_unique_private_id(h)?;
    }
    tok.check_public_half(h, t.spec, &t.on_token.locator, public_only)?;
    let Computed { ids, binding, commitment_label, spki, commits } = compute_ids(t, tok, lock, h, mode)?;
    // The key's public key, read once (review D8): every check below compares with the value its
    // identity hashed. A key identified another way reads it where it is needed.
    let spki = || spki.clone().map_or_else(|| tok.spki(h, &t.on_token.locator), Ok);
    // After the IDs, so a swapped private key still reports its failed proof first.
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
        uri: tok.uri(t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(t.object, t.spec),
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
    /// How a private key is bound: observed, not planned (a `CKA_ALWAYS_AUTHENTICATE` key
    /// records the `pop-sign-pin` it proved).
    binding: Option<cakeys_core::config::Binding>,
    /// The label the commitments were computed with, when there are any.
    commitment_label: Option<String>,
    /// The key's canonical SPKI, where its identity is one (an asymmetric key, `Direct`).
    spki: Option<Vec<u8>>,
    /// The commitments computed (a secret key's), under `commitment_label`.
    commits: Vec<Commit>,
}

/// The commitments `commits` computed under `label`, each with its input and the ID it gave
/// (`ids`): what a secret key's attestation is bound to (review 2026-11-23 B-1).
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
            Some(crate::provider::Commitment { commit: *c, input: c.input(label, t.object), id })
        })
        .collect()
}

/// The material IDs of `t`'s object `h` on `tok` in `mode` — a private key proving possession
/// on the way — as `resolve` and `delete` (If-Match) compute them.
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

/// The attestation commitment (§3.7): per-device identity from signed provenance. The material
/// SPKI it must name comes from the same source `rfc7093m4` hashed, so an attestation of other
/// material is a conflict, not a second opinion.
///
/// Once the lock pins an attestation for this realisation, a run that cannot attest — the TPM
/// unreachable, no PIN, no attestation certificate — is a scheme downgrade (14), like any
/// scheme a realisation stops computing. Conflicts (13) and ambiguity (12) keep their codes:
/// they say the evidence is wrong, not absent.
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
    let a = match tok.attest(h, t.object, spki, commitments, provision == Provision::IfMissing) {
        Ok(a) => a,
        Err(e @ (KmError::Unavailable(_) | KmError::Unsupported(_) | KmError::NotFound(_))) => {
            let locked = lock.realisation(t.spec_name, t.token_name).and_then(|r| r.attestation.as_ref());
            return Err(match locked {
                Some(was) => KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it cannot compute now: {e}",
                    t, was.kind
                ).into()),
                None => e,
            });
        }
        Err(e) => return Err(e),
    };
    if a.scheme != scheme {
        return Err(KmError::Conflict(
            format!("provider '{}' advertises {scheme} but attested {}", tok.provider.name(), a.scheme).into(),
        ));
    }
    if let Some(w) = &a.warning {
        notes.warn(format!("{t}: its attestation would fail `check` today: {w}"));
    }
    if let Some(c) = &a.caveat {
        notes.warn(format!("{t}: {c}"));
    }
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// What a run did with its key, for [`answers`]: found it under its locator, or created it,
/// with how the module made it when that was other than asked.
#[derive(Clone, Copy)]
enum Run<'a> {
    Found,
    Created(Option<&'a hal::CreateNote>),
}

/// What `t`'s run on its token demonstrated, as capability rows (docs/CAPROBE.md): the proof of
/// possession it gave, and the generation when it created the key, `via = "by-name"` when the
/// module took the curve only by name (ISSUES.md B18). A run that failed records nothing, so
/// these are only ever yes.
fn answers(t: &Target, r: &Resolved, run: Run<'_>) -> std::collections::BTreeMap<String, Answered> {
    let mut out = std::collections::BTreeMap::new();
    if !t.object.class.is_asymmetric() {
        return out;
    }
    // The rows' own keys (`cakeys_profile::Capability`), as the gate reads them back.
    if let Some(proof) = r.binding.and_then(|b| crate::gate::proof_capability(t.object, b)) {
        out.insert(proof.to_string(), Answered::yes());
    }
    if let Run::Created(note) = run
        && let Some(generated) = crate::gate::generate_capability(t.object)
    {
        let via = note.and_then(|n| n.by_name.as_ref()).map(|_| "by-name".to_owned());
        out.insert(generated.to_string(), Answered { via, ..Answered::yes() });
    }
    out
}

/// What this run sees of `tok` (session, mechanisms, profile, module, token), and what `t`'s
/// run demonstrated ([`answers`]), for the lock to record or compare.
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

/// GET + If-Match against the lock. Never writes, neither the lock nor the token.
///
/// # Errors
///
/// `NotFound` when resolve found nothing (`cakeys create` makes it); whatever `compare`
/// rejects — `HashMismatch` (10) when the token's IDs differ from the lock,
/// `PreconditionFailed` (14) for a realisation that moved.
pub fn verify(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Resolved> {
    let r = resolve(t, tok, lock, notes)?.ok_or_else(|| absent(t))?;
    reconcile::compare(t, &r, lock, &facts(t, tok, &r, Run::Found), LockWrite::Compare, notes)?;
    Ok(r)
}

/// The lock verb: find the object, compare it with the lock and record what the lock lacks or
/// what changed around it (docs/CAKEYS.md). Never creates the object (`create` does); it does
/// provision a TPM Attestation Key the realisation needs.
///
/// # Errors
///
/// `NotFound` when the locator finds nothing; whatever `resolve` returns for the object once
/// found; `plan_mode`/`check_capabilities` rejections (`Validation`, `Unsupported`) before the
/// object is looked for, and `compare`'s on the realised object.
pub fn lock(t: &Target, tok: &Token, lock: &mut Lock, write: LockWrite, notes: &mut Notes) -> Result<(Resolved, bool)> {
    lock_as(t, tok, lock, write, None, notes)
}

/// Record an object camigrate just imported (docs/CAMIGRATE.md D6, D7): [`lock`] without creating,
/// through the same lock rules, with the realisation's `provenance.origin` saying where the
/// material came from. The lock must already pin the object's IDs (they came from the source),
/// so a different material is a mismatch (10), never a new identity.
///
/// # Errors
///
/// `NotFound` when the object is not under the locator; whatever [`lock`] refuses for an
/// object it found, a hash mismatch (10) included; `PreconditionFailed` when the lock pins no
/// ID for the object (`reconcile` refuses an import that would be a first use).
pub fn lock_import(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    origin: Origin,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    lock_as(t, tok, lock, LockWrite::Record, Some(origin), notes)
}

/// [`lock`]'s one code path: `origin` records an import's history.
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

/// `NotFound` for `t`'s object missing under its locator, naming what puts it there: its
/// pair's origin says which verb.
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

/// Create `t`'s object, which `resolve` did not find, and resolve it. Refused before anything is
/// created when the lock pins the object (D1), a session without login cannot see the locator,
/// or anything sits under it; what was created is removed again when its identity cannot be
/// established.
/// Returns what was made and how the module made it, when other than asked.
fn create_absent(
    t: &Target,
    tok: &Token,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(Resolved, Option<hal::CreateNote>)> {
    // If-None-Match: never create over anything else under the locator. On a PIV token,
    // generating into an occupied slot would silently replace its key. A session without login
    // sees no private object, so it cannot tell the locator is free — nor that a private or
    // secret key the lock pins is gone, which D1 below would say.
    let no_login = || {
        KmError::Unavailable(
            format!(
                "{t}: a session without login cannot see private objects under the locator, so it cannot \
             tell the locator is free; configure pinFile or pinEnv for token '{}'",
                t.token_name
            )
            .into(),
        )
    };
    if !tok.logged_in && matches!(t.object.class, Class::PrivateKey | Class::SecretKey) {
        return Err(no_login());
    }
    // D1: the lock already pins this object's material, so a fresh generation can only end in a
    // mismatch; refuse before anything is created. (Had this token held the same material,
    // resolve would have found it.)
    if let Some(ids) = lock.objects.get(t.object_name).map(|o| &o.ids).filter(|ids| !ids.is_empty()) {
        return Err(KmError::PreconditionFailed(format!(
            "{}: the lock already pins object '{}' ({}); creating it would generate different material that can never match; put the same material under \
             the locator, or give this token's key its own object name",
            t,
            t.object_name,
            ids.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
        ).into()));
    }
    if !tok.logged_in {
        return Err(no_login());
    }
    // Any class, unlike an import (`Token::occupied`): a certificate already there certifies
    // some other key, never one generated now.
    let present = tok.find_any(&t.on_token.locator)?;
    if !present.is_empty() {
        return Err(KmError::Conflict(
            format!(
                "{} objects of another class already sit under the locator of {}; refusing to create",
                present.len(),
                t
            )
            .into(),
        ));
    }
    let made_otherwise = match tok.create(t.object, t.spec, &t.on_token.locator, cakeys_core::plan::expected_binding(t))
    {
        Ok(made) => made,
        // A module may fail after it made the key (an error after the write, or the session
        // put back after an SO step): what is under the locator now is this creation's.
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

/// After a creation under `t`'s locator that failed (`why`): remove what is there. The locator
/// was empty before (If-None-Match), so this removes only what the creation made: a refused
/// creation or `lock` leaves nothing behind, unless the module cannot delete keys (ykcs11),
/// which is then said rather than claimed. Hands back `err`.
fn undo_created(t: &Target, tok: &Token, err: KmError, why: &str, notes: &mut Notes) -> KmError {
    match tok.find_any(&t.on_token.locator) {
        Ok(found) if found.is_empty() => {}
        Ok(_) => match tok.destroy(t.object, &t.on_token.locator) {
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

/// What [`create`] did with its pair.
#[derive(Debug)]
pub enum Made {
    /// Created and recorded; whether the lock changed.
    Created(Resolved, bool),
    /// Already there, and the lock pins it: verified as `check` verifies it, nothing made and
    /// nothing written.
    Verified(Resolved),
}

/// PUT If-None-Match: create the object under the declared locator, then record it as [`lock`]
/// does. The one verb that creates, and only on a pair whose `origin` is `create`. A key the
/// lock pins that is already under the locator is verified as `check` verifies it ([`verify`])
/// and left alone; one the lock does not pin is `Exists` (19), whatever it holds, before any
/// capability is asked of the token — `lock` is the verb for a key that is there. Every other
/// guard of a creation applies: the lock must not pin the object's material already (D1), and
/// nothing of another class may sit under the locator.
///
/// # Errors
///
/// `Validation` (17) on a pair whose origin is not `create`, before the token is touched;
/// [`verify`]'s errors for a pinned key that is there (`HashMismatch` (10) for other material,
/// `PreconditionFailed` (14) for a realisation the lock does not record or that moved);
/// `Exists` (19) when an unpinned key is already under its locator, `Ambiguous` when several
/// are; `plan_mode`/`check_capabilities` rejections, the generation included;
/// `PreconditionFailed` (D1) when the lock pins the object's material and the token lost it,
/// `Unavailable` when a session without login cannot see the locator, `Conflict` when the
/// locator is occupied by another class; and `compare`'s on the object just made.
pub fn create(t: &Target, tok: &Token, lock: &mut Lock, write: LockWrite, notes: &mut Notes) -> Result<Made> {
    let mode = plan_mode(t)?;
    if let Some(why) = not_origin_create(t) {
        return Err(KmError::Validation(format!("{t}: {why}").into()));
    }
    if tok.find_key(t.object, &t.on_token.locator, false)?.is_some() {
        if pinned(t, lock).is_none() {
            return Err(KmError::Exists(
                format!(
                    "{t} is already under its locator: nothing was created; `cakeys lock` records a key that is there"
                )
                .into(),
            ));
        }
        let r = verify(t, tok, lock, notes)?;
        notes.say(format!("{t} is already there and matches the lock: nothing created"));
        return Ok(Made::Verified(r));
    }
    check_capabilities(t, tok, mode, Verb::Create)?;
    let (r, note) = create_absent(t, tok, lock, notes)?;
    let changed = reconcile::reconcile(t, &r, lock, &facts(t, tok, &r, Run::Created(note.as_ref())), write, notes)?;
    Ok(Made::Created(r, changed))
}

/// What [`delete`] did with the object under the locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deleted {
    /// It held the expected identity and was destroyed.
    Deleted,
    /// It holds the expected identity: a run without `dry_run` destroys it.
    WouldDelete,
    /// Nothing is under the locator.
    Absent,
}

impl Deleted {
    /// Its name in `cakeys delete`'s output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Deleted::Deleted => "deleted",
            Deleted::WouldDelete => "would-delete",
            Deleted::Absent => "absent",
        }
    }
}

/// DELETE + If-Match. Absent is success; only the object identified (and a private key's public
/// half holding the same key) is removed: anything else under the locator is left alone, and the
/// realisation is removed from the lock (its object's `ids` stay: the material may live on other
/// tokens). `dry_run` identifies and checks If-Match as a delete does, and changes nothing.
/// Returns what it did, and whether it changed the lock.
///
/// # Errors
///
/// `Unsupported` for a `publicOnly` adoption or when no identity can be computed to check;
/// `Unavailable` when a session without login finds no private object (it cannot see one);
/// `PreconditionFailed` when there is nothing to check against (no `--if-match`, no locked
/// ID) or the token holds another ID than expected. `destroy` keeps its own refusals (15).
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
    if let Some(h) = tok.find_key(t.object, loc, false)? {
        // Proven like `resolve`: If-Match must not pass on a public object beside another key.
        let Computed { ids: got, spki, .. } = compute_ids(t, tok, lock, h, plan_mode(t)?)?;
        // The schemes computed, in the spec's order of preference: the first is the primary one.
        let computed: Vec<Scheme> = t.schemes().into_iter().filter(|s| got.contains_key(s.name())).collect();
        let primary =
            *computed.first().ok_or_else(|| KmError::Unsupported(format!("no identity computed for {t}").into()))?;
        // --if-match names the primary scheme; otherwise the first scheme the lock records.
        let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
        let (scheme, expected) = match if_match {
            Some(want) => (primary, want.to_owned()),
            None => computed.iter().find_map(|s| Some((*s, locked?.get(s.name())?.clone()))).ok_or_else(|| {
                KmError::PreconditionFailed(format!("no expected {primary} for {t}; pass --if-match").into())
            })?,
        };
        if got.get(scheme.name()) != Some(&expected) {
            return Err(KmError::PreconditionFailed(
                format!("{} holds {:?}, expected {expected}; not deleting", t, got.get(scheme.name())).into(),
            ));
        }
        if dry_run {
            notes.say(format!("{t} holds {expected}: a delete would destroy it"));
            return Ok((Deleted::WouldDelete, false));
        }
        let (n, left) = tok.destroy_identified(h, t.object, loc, spki.as_deref())?;
        outcome = Deleted::Deleted;
        notes.say(format!("destroyed {n} object(s) for {t}"));
        if left > 0 {
            notes
                .note(format_args!("left {left} public key object(s) under the locator of {t}: they hold another key"));
        }
    } else if !tok.logged_in && matches!(t.object.class, Class::PrivateKey | Class::SecretKey) {
        return Err(KmError::Unavailable(
            format!(
                "{t}: a session without login cannot see private objects, so it cannot tell the key is absent; \
             configure pinFile or pinEnv for token '{}'",
                t.token_name
            )
            .into(),
        ));
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

/// A `check` reference in its parts: the object, and the scheme `<object>.id.<scheme>` asks for.
#[must_use]
pub fn split_reference(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once(".id.") {
        Some((object, scheme)) => (object, Some(scheme)),
        None => (reference, None),
    }
}

/// The pseudo-FOD pre-use check of `reference` (`<object>` or `<object>.id.<scheme>`; none with `spec`): pick the
/// (spec, token) pair and [`verify`] it, in a read-only session. Never writes: neither the lock,
/// nor the token, nor a TPM's persistent handles; an object that is not there is `NotFound`
/// (`cakeys create` makes it), one that is there but not locked fails with its `got:` (10).
/// A requested scheme must be one the spec computes on this token — refused (15) before the
/// token is opened, or before the object is looked for — and must itself be locked, not merely
/// computed beside another scheme that matched (18, a first use of that scheme, with its
/// `got:`). `open` opens the token.
///
/// # Errors
///
/// `Unsupported` (15) for a scheme the spec does not compute on this token; `FirstUse` (18)
/// when a requested scheme is computed but not locked (its `got:` shows the computed ID); plus `Config::address`/`Target::new`/`verify` failures — the reference and the pair must
/// exist, and the realisation must compare clean.
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

/// [`check`], also handing back the token it opened, for a caller that reads more of the
/// object it verified (the CLI's key-file output asks for its `CKA_ID`).
///
/// # Errors
///
/// As [`check`].
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
    // Refused before the token opens where the spec cannot compute it at all.
    let scheme = requested.map(|name| requested_scheme(&t, name, None)).transpose()?;
    let tok = open(&token_name, hal::Access::Read)?;
    if let Some(w) = tok.pin_warning() {
        notes.warn(w);
    }
    // The token may lack a mechanism the spec allows: refuse before the object is looked for.
    if let Some(s) = scheme {
        requested_scheme(&t, s.name(), Some(&schemes_on(&t, &tok)?))?;
    }
    let r = verify(&t, &tok, lock, notes)?;
    // An attestation is locked on this realisation (§3.7), not on the object.
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

/// The scheme `name` a reference asks of `t` (`<object>#<scheme>`), refused (15) in one wording
/// whether asked before the token opens (`on_token` `None`: the spec's own schemes, and any
/// attestation scheme where it opted in, which only the provider decides) or after (what the
/// token computes, [`schemes_on`]): one mistake, one message (ops F4).
///
/// # Errors
///
/// `Unsupported` for a scheme the spec does not compute there, or no scheme at all.
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

/// One (spec, token) pair [`check_token`] verified, and how that went.
pub struct PairCheck {
    /// The spec realising the object.
    pub spec: String,
    /// The object it realises.
    pub object: String,
    /// What [`verify`] made of it.
    pub result: Result<Resolved>,
}

/// [`check`] of every (spec, token) pair keys.toml places on `token`, in one read-only session:
/// a failing pair does not stop the others, each one's result is handed back. Never writes.
/// `open` opens the token.
///
/// # Errors
///
/// `Validation` (17) for a token keys.toml does not name or that no spec places anything on;
/// whatever `open` refuses. A pair's own failure is in its [`PairCheck`], never here.
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

    /// A scheme a reference asks for is refused in one wording before the token opens and after
    /// (ops F4): before, by the spec's schemes and (opted in) any attestation scheme; after, by
    /// what the token computes.
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
