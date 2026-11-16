//! Idempotent verbs with HTTP-like semantics (docs/CAKEYS.md).

use crate::provider::Provider;
use crate::token::{self as hal, Token};
use cakeys_core::config::{AttestationRecord, Config, Lock, Mode, Observation, Observed, Origin, Session};
use cakeys_core::id::{self, Commit, HmacHash, Scheme};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};

pub use cakeys_core::plan::{Target, binding, plan_mode};
use cakeys_core::plan::{block_commits, declared_commits};
use cakeys_core::reconcile::{self, commitment_label};
pub use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved};

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

/// What a target needs of its token, whatever the token: the one source of truth for the live
/// check before anything is created (`check_capabilities`) and the static gate against the
/// capability profiles ([`crate::gate::check`], docs/CAPROBE.md).
pub struct Needs {
    /// Mechanism groups in check order: the token must implement at least one of each.
    pub groups: Vec<Vec<MechanismType>>,
    /// What `create` needs besides: the mechanism that generates the object. Its key type,
    /// curve and size must be generatable too. `None` when not creating.
    pub generation: Option<MechanismType>,
}

/// Whether `t`'s object, created, is generated from the module's own template
/// ([`Provider::generation`]). The provider's refusal of a key it could not make as declared is
/// the error, before anything is created.
///
/// # Errors
///
/// The provider's refusal.
pub fn own_generation(t: &Target, provider: &dyn Provider) -> Result<bool> {
    let binding = cakeys_core::plan::expected_binding(t);
    Ok(provider.generation(t.object, t.spec, &t.on_token.locator, binding)?.is_some())
}

/// [`Needs`] of `t` in `mode`. `creating`, when `create` makes the object: `Some` of
/// [`own_generation`] (the module generates it from its own template, which may make what a
/// standard template cannot). Every other verb finds an object that is there.
///
/// # Errors
///
/// `Unsupported` for a key type cakeys does not manage.
pub fn needs(t: &Target, mode: Mode, creating: Option<bool>) -> Result<Needs> {
    let mut groups = Vec::new();
    // The commitments first: a token implementing none of them is the more telling refusal.
    let commits = wanted_commits(t, mode);
    if !commits.is_empty() {
        groups.push(commits.iter().map(|c| hal::commit_mechanism(*c)).collect());
    }
    if mode == Mode::WrapRebind {
        groups.push(vec![MechanismType::AES_KEY_GEN]);
        groups.push(vec![MechanismType::AES_KEY_WRAP_PAD, MechanismType::AES_KEY_WRAP]);
    }
    let generation = match creating {
        None => None,
        Some(own_generation) => {
            // A hash-bound HMAC type generates with its own CKM_SHA*_KEY_GEN, unless the module
            // generates it its own way (libkmsp11).
            let hmac = t.object.key_type.and_then(hal::hmac_key_gen).filter(|_| !own_generation);
            Some(match (hmac, hal::key_type_of(t.object)?) {
                (Some(m), _) => m.mechanism_type(),
                (None, KeyType::EC) => MechanismType::ECC_KEY_PAIR_GEN,
                (None, KeyType::EC_EDWARDS) => MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
                (None, KeyType::RSA) => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
                (None, KeyType::AES) => MechanismType::AES_KEY_GEN,
                (None, KeyType::DES3) => MechanismType::DES3_KEY_GEN,
                (None, _) => MechanismType::GENERIC_SECRET_KEY_GEN,
            })
        }
    };
    Ok(Needs { groups, generation })
}

/// The refusal for a mechanism group the token lacks.
fn lacking(token: &str, group: &[MechanismType], mode: Mode, t: &Target) -> String {
    if let [m] = group {
        return format!("token '{token}' lacks {m} needed for mode '{mode}' of {t}");
    }
    let names: Vec<String> = group.iter().map(ToString::to_string).collect();
    format!("token '{token}' implements none of {} needed for mode '{mode}' of {t}", names.join(", "))
}

/// An attestation the provider cannot compute is refused up front (15), like a scheme the
/// token lacks: it is part of the identity the realisation promises from now on.
pub(crate) fn check_attestation(
    t: &Target,
    provider: &dyn crate::provider::Provider,
) -> std::result::Result<(), String> {
    if !t.on_token.attestation {
        return Ok(());
    }
    match provider.attestation() {
        None => {
            Err(format!("{t} opts into attestation, but provider '{}' attests nothing on this module", provider.name()))
        }
        Some(cap) if !cap.classes.contains(&t.object.class) => Err(format!(
            "{t} opts into attestation, but provider '{}' attests only {:?}",
            provider.name(),
            cap.classes.iter().map(|c| c.name()).collect::<Vec<_>>()
        )),
        Some(_) => Ok(()),
    }
}

/// Token capabilities the mode needs, and when `creating` the generation, checked before
/// anything is created.
fn check_capabilities(t: &Target, tok: &Token, mode: Mode, creating: bool) -> Result<()> {
    let to_token = |e| match e {
        KmError::Unsupported(m) => tok.unsupported(m),
        e => e,
    };
    let own = if creating { Some(own_generation(t, tok.provider.as_ref()).map_err(to_token)?) } else { None };
    let needs = needs(t, mode, own).map_err(to_token)?;
    check_attestation(t, tok.provider.as_ref()).map_err(|m| tok.unsupported(m))?;
    let generation = needs.generation.map(|m| vec![m]);
    if let Some(g) = needs.groups.iter().chain(&generation).find(|g| !g.iter().any(|m| tok.has(*m))) {
        return Err(tok.unsupported(lacking(&tok.name, g, mode, t)));
    }
    // The proof the realisation will make, as the spec says it (camigrate's plan asks the same).
    match cakeys_core::plan::expected_binding(t) {
        Some(b) => tok.check_proof(t.object, b),
        None => Ok(()),
    }
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes,
/// neither the lock nor the token: a TPM Attestation Key that is not provisioned yet is an
/// error here, and only `realise` provisions it.
///
/// # Errors
///
/// `NotFound` when the locator finds no object, `Ambiguous` when it finds several; `Conflict`
/// for a wrong type or policy, or — for a private key — a public key object under the locator
/// that holds another key; `Unsupported`/`Unavailable` when the object cannot be proven or
/// attested as the spec requires.
pub fn resolve(t: &Target, tok: &Token, lock: &Lock) -> Result<Option<Resolved>> {
    resolve_with(t, tok, lock, false)
}

fn resolve_with(t: &Target, tok: &Token, lock: &Lock, provision: bool) -> Result<Option<Resolved>> {
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
    let Computed { ids, binding, commitment_label } = compute_ids(t, tok, lock, h, mode)?;
    // After the IDs, so a swapped private key still reports its failed proof first.
    if t.object.class == Class::PrivateKey && !public_only {
        tok.check_public_objects(h, &t.on_token.locator)?;
    }
    let attestation = match attestation_scheme(t, tok) {
        Some(scheme) => Some(attest(t, tok, lock, h, scheme, provision)?),
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
        immutables: tok.immutables(h),
        commitment_label,
        attestation,
        public_key: if t.transport { Some(tok.spki(h, &t.on_token.locator)?) } else { None },
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
}

/// The material IDs of `t`'s object `h` on `tok` in `mode` — a private key proving possession
/// on the way — as `resolve` and `delete` (If-Match) compute them.
fn compute_ids(t: &Target, tok: &Token, lock: &Lock, h: ObjectHandle, mode: Mode) -> Result<Computed> {
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    let binding = tok.recorded_binding(h, binding(t))?;
    let ids = tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label, binding)?;
    Ok(Computed { ids, binding, commitment_label: (!commits.is_empty()).then_some(label) })
}

/// The attestation commitment (§3.7): per-device identity from signed provenance. The material
/// SPKI it must name comes from the same source `rfc7093m4` hashed, so an attestation of other
/// material is a conflict, not a second opinion.
///
/// Once the lock pins an attestation for this realisation, a run that cannot attest — the TPM
/// unreachable, no PIN, no attestation certificate — is a scheme downgrade (14), like any
/// scheme a realisation stops computing. Conflicts (13) and ambiguity (12) keep their codes:
/// they say the evidence is wrong, not absent.
fn attest(
    t: &Target,
    tok: &Token,
    lock: &Lock,
    h: ObjectHandle,
    scheme: Scheme,
    provision: bool,
) -> Result<AttestationRecord> {
    let asymmetric = t.object.class.is_asymmetric();
    let spki = if asymmetric { Some(tok.spki(h, &t.on_token.locator)?) } else { None };
    let kind = scheme.attestation_kind().ok_or_else(|| {
        KmError::Unsupported(format!(
            "provider '{}' advertises unknown attestation scheme {scheme}",
            tok.provider.name()
        ))
    })?;
    let a = match tok.attest(h, t.object, spki.as_deref(), provision) {
        Ok(a) => a,
        Err(e @ (KmError::Unavailable(_) | KmError::Unsupported(_) | KmError::NotFound(_))) => {
            let locked = lock.realisation(t.spec_name, t.token_name).and_then(|r| r.attestation.as_ref());
            return Err(match locked {
                Some(was) => KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it cannot compute now: {e}",
                    t, was.kind
                )),
                None => e,
            });
        }
        Err(e) => return Err(e),
    };
    if a.scheme != scheme {
        return Err(KmError::Conflict(format!(
            "provider '{}' advertises {scheme} but attested {}",
            tok.provider.name(),
            a.scheme
        )));
    }
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// What this run sees of `tok` (session, mechanisms, profile, module, token), for the lock to
/// record or compare.
fn facts(tok: &Token, r: &Resolved) -> Facts {
    Facts {
        observed: Observed { uri: r.uri.clone(), session: if tok.logged_in { Session::User } else { Session::Public } },
        observation: Observation {
            provider: Some(tok.provider.name().to_owned()),
            cakeys_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            profile: tok.profiles.module_name().map(str::to_owned),
            mechanisms: tok.mechanism_names().to_vec(),
            module: Some(tok.module.clone()),
            token: Some(tok.token.clone()),
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
    let r = resolve(t, tok, lock)?
        .ok_or_else(|| KmError::NotFound(format!("{t}: not under its locator; `cakeys create` makes it")))?;
    reconcile::compare(t, &r, lock, &facts(tok, &r), LockWrite::Compare, notes)?;
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
pub fn realise(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    realise_as(t, tok, lock, write, false, None, notes)
}

/// Record an object camigrate just imported (docs/CAMIGRATE.md D6, D7): [`realise`] without creating,
/// through the same lock rules, with the realisation's `provenance.origin` saying where the
/// material came from. The lock must already pin the object's IDs (they came from the source),
/// so a different material is a mismatch (10), never a new identity.
///
/// # Errors
///
/// `NotFound` when the object is not under the locator; whatever [`realise`] refuses for an
/// object it found, a hash mismatch (10) included; `PreconditionFailed` when the lock pins no
/// ID for the object (`reconcile` refuses an import that would be a first use).
pub fn realise_import(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    origin: Origin,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    realise_as(t, tok, lock, LockWrite::Record, false, Some(origin), notes)
}

/// [`realise`]'s one code path: `create` allows creating an absent object, `origin` records an
/// import's history.
fn realise_as(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    write: LockWrite,
    create: bool,
    origin: Option<Origin>,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode, create)?;
    let r = match resolve_with(t, tok, lock, true)? {
        Some(r) => r,
        None if create => create_absent(t, tok, lock, notes)?,
        None => return Err(KmError::NotFound(format!("{t}: not under its locator; `cakeys create` makes it"))),
    };
    let facts = Facts { origin, ..facts(tok, &r) };
    let changed = reconcile::reconcile(t, &r, lock, &facts, write, notes)?;
    Ok((r, changed))
}

/// Create `t`'s object, which `resolve` did not find, and resolve it. Refused before anything is
/// created when the lock pins the object (D1), a session without login cannot see the locator,
/// or anything sits under it; what was created is removed again when its identity cannot be
/// established.
fn create_absent(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Resolved> {
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
        )));
    }
    // If-None-Match: never create over anything else under the locator. On a PIV token,
    // generating into an occupied slot would silently replace its key. A session without login
    // sees no private object, so it cannot tell the locator is free.
    if !tok.logged_in {
        return Err(KmError::Unavailable(format!(
            "{t}: a session without login cannot see private objects under the locator, so it cannot \
             tell the locator is free; configure pinFile or pinEnv for token '{}'",
            t.token_name
        )));
    }
    // Any class, unlike an import (`Token::occupied`): a certificate already there certifies
    // some other key, never one generated now.
    let present = tok.find_any(&t.on_token.locator)?;
    if !present.is_empty() {
        return Err(KmError::Conflict(format!(
            "{} objects of another class already sit under the locator of {}; refusing to create",
            present.len(),
            t
        )));
    }
    let made_otherwise = tok.create(t.object, t.spec, &t.on_token.locator, cakeys_core::plan::expected_binding(t))?;
    notes.say(format!("created {t}"));
    if let Some(note) = made_otherwise {
        notes.say(note);
    }
    let e = match resolve_with(t, tok, lock, true) {
        Ok(Some(r)) => return Ok(r),
        Ok(None) => KmError::NotFound(format!("{t} vanished after creation")),
        Err(e) => e,
    };
    // The locator was empty before (If-None-Match), so this removes only what we just made: a
    // refused realise leaves nothing behind, unless the module cannot delete keys (ykcs11),
    // which is then said rather than claimed.
    match tok.destroy(t.object, &t.on_token.locator) {
        Ok(n) => {
            notes.say(format!("removed {n} object(s) just created for {t}: its identity could not be established"));
        }
        Err(d) => notes.say(format!(
            "the key just created for {t} is still on the token (its identity could not be established, \
             and removing it failed: {d})"
        )),
    }
    Err(e)
}

/// PUT If-None-Match: create the object under the declared locator if absent, then
/// [`realise`] it. The one verb that creates. Every guard of a creation applies: the class
/// must be one cakeys generates, the lock must not pin the object's material already (D1), and
/// nothing may sit under the locator; an object already there is found and compared, never
/// replaced.
///
/// # Errors
///
/// As [`realise`], and for the creation: `PreconditionFailed` (D1) when the lock already pins
/// the object's material, `Unavailable` when a session without login cannot see the locator,
/// `Conflict` when the locator is occupied by another class; `Validation` (17) for an object
/// cakeys does not create (`plan::not_creatable`) or on a token other than the object's
/// `createOn`, before the token is touched.
pub fn create(
    t: &Target,
    tok: &Token,
    lock: &mut Lock,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<(Resolved, bool)> {
    plan_mode(t)?;
    if let Some(why) = cakeys_core::plan::not_creatable(t).map(str::to_owned).or_else(|| born_elsewhere(t)) {
        return Err(KmError::Validation(format!("{t}: {why}")));
    }
    realise_as(t, tok, lock, write, true, None, notes)
}

/// Why `t`'s token may not create its object: keys.toml names another as its `createOn`.
fn born_elsewhere(t: &Target) -> Option<String> {
    t.create_on.filter(|born| *born != t.token_name).map(|born| {
        format!(
            "object '{}' is created on '{born}' (createOn); import it from there (camigrate migrate {} --from \
             {born} --to {})",
            t.object_name, t.object_name, t.token_name
        )
    })
}

/// Why `create` without a named pair leaves `t` alone: a class cakeys adopts rather than
/// generates, a publicOnly adoption, an object born on another token (`createOn`), or an object
/// whose material the lock already pins (another token then needs that same material, which
/// only importing or migrating can put there).
fn not_created(t: &Target, lock: &Lock) -> Option<String> {
    if let Some(why) = cakeys_core::plan::not_creatable(t) {
        return Some(why.to_owned());
    }
    if let Some(why) = born_elsewhere(t) {
        return Some(why);
    }
    lock.objects.get(t.object_name).filter(|o| !o.ids.is_empty()).map(|_| {
        format!(
            "the lock already pins object '{}' (`verify` checks it; a token without it needs that same \
             material imported, never a new key)",
            t.object_name
        )
    })
}

/// Whether `create`, naming no pair, would make `t`'s object: it is a class cakeys creates, not
/// born on another token, and not pinned by the lock. What the static gate checks generation for.
#[must_use]
pub fn creates(t: &Target, lock: &Lock) -> bool {
    not_created(t, lock).is_none()
}

/// The (spec, token) pairs `create` selects, in config order.
///
/// # Errors
///
/// A name that selects nothing is refused like the other verbs refuse it: an unknown spec
/// (`NotFound`) or token (`Validation`), or a spec without that token (`NotFound`).
pub fn create_pairs<'a>(cfg: &'a Config, spec: Option<&str>, token: Option<&str>) -> Result<Vec<(&'a str, &'a str)>> {
    if let Some(s) = spec
        && !cfg.specs.contains_key(s)
    {
        return Err(KmError::NotFound(format!("spec '{s}'")));
    }
    if let Some(t) = token
        && !cfg.tokens.contains_key(t)
    {
        return Err(KmError::Validation(format!("unknown token '{t}'")));
    }
    if let (Some(s), Some(t)) = (spec, token) {
        Target::new(cfg, s, t)?;
    }
    Ok(cfg
        .specs
        .iter()
        .filter(|(n, _)| spec.is_none_or(|s| s == n.as_str()))
        .flat_map(|(n, s)| s.tokens.keys().map(move |t| (n.as_str(), t.as_str())))
        .filter(|(_, t)| token.is_none_or(|w| w == *t))
        .collect())
}

/// What `create` over `pairs` would otherwise decide by the order it runs in: an object several
/// selected specs would create on one token (which spec's policy it is born with), and one it
/// would create on several tokens without `createOn` (where it is born; and without the lock
/// written, nothing would pin the first, so each token would get material of its own). Only
/// the pairs `create` would make count ([`not_created`]), so a pinned object never refuses.
///
/// # Errors
///
/// `Ambiguous` (12) naming the specs or the tokens, as `Config::pick_spec` does for a reference
/// several pairs match; `Target::new`'s refusals.
fn unordered_births(cfg: &Config, pairs: &[(&str, &str)], lock: &Lock) -> Result<()> {
    use std::collections::BTreeMap;
    // object -> token -> the specs that would create it there
    let mut births: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for &(spec_name, token_name) in pairs {
        let t = Target::new(cfg, spec_name, token_name)?;
        if not_created(&t, lock).is_none() {
            births.entry(t.object_name).or_default().entry(token_name).or_default().push(spec_name);
        }
    }
    for (object, tokens) in &births {
        if let Some((token, specs)) = tokens.iter().find(|(_, specs)| specs.len() > 1) {
            return Err(KmError::Ambiguous(format!(
                "object '{object}' would be created on token '{token}' by several specs ({}), each with its \
                 own policy: name the one it is created with (`cakeys create <spec>`)",
                specs.join(", ")
            )));
        }
        if tokens.len() > 1 {
            return Err(KmError::Ambiguous(format!(
                "object '{object}' would be created on several tokens ({}), each with material of its own: name \
                 the one it is born on with createOn, or the pair (`cakeys create <spec> --token <token>`); the \
                 others get it by import (camigrate migrate)",
                tokens.keys().copied().collect::<Vec<_>>().join(", ")
            )));
        }
    }
    Ok(())
}

/// What [`create_selected`] did.
pub struct Created {
    /// The realised objects, in the order they were created.
    pub created: Vec<Resolved>,
    /// Whether the lock changed: the caller saves it, also when `failed` is set — never a key
    /// made and lost.
    pub changed: bool,
    /// The failure that ended the run, if any.
    pub failed: Option<KmError>,
}

/// The `create` verb: [`create`] over every selected pair ([`create_pairs`]) whose object the
/// lock does not pin yet; pinned, adopted-only and publicOnly pairs are skipped with a note,
/// unless both `spec` and `token` name the pair. Every step of a pair, opening its token
/// included, ends the run there, reported in [`Created::failed`] beside what was created
/// before.
///
/// At most one token is open at a time: each is closed before the next opens.
///
/// # Errors
///
/// [`create_pairs`]' refusals, and an object only the order of the run would decide (12: one
/// object created by several specs on one token, or on several tokens without `createOn`)
/// unless both `spec` and `token` name the pair, before any token is opened.
pub fn create_selected(
    cfg: &Config,
    spec: Option<&str>,
    token: Option<&str>,
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    lock: &mut Lock,
    write: LockWrite,
    notes: &mut Notes,
) -> Result<Created> {
    let pairs = create_pairs(cfg, spec, token)?;
    let named = spec.is_some() && token.is_some();
    if !named {
        unordered_births(cfg, &pairs, lock)?;
    }
    let mut out = Created { created: Vec::new(), changed: false, failed: None };
    let mut current: Option<Token> = None;
    for (spec_name, token_name) in pairs {
        let mut pair = || -> Result<Option<(Resolved, bool)>> {
            let t = Target::new(cfg, spec_name, token_name)?;
            if !named && let Some(why) = not_created(&t, lock) {
                notes.note(format_args!("create: skipped {t}: {why}"));
                return Ok(None);
            }
            // Another token's module is finalized (dropped) before the next open.
            let tok = match current.take().filter(|tok| tok.name == token_name) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token_name, notes)?),
            };
            create(&t, tok, lock, write, notes).map(Some)
        };
        match pair() {
            Ok(Some((r, c))) => {
                out.changed |= c;
                out.created.push(r);
            }
            Ok(None) => {}
            Err(e) => {
                out.failed = Some(e);
                break;
            }
        }
    }
    Ok(out)
}

/// DELETE + If-Match. Absent is success; only the object identified (and a private key's public
/// half holding the same key) is removed: anything else under the locator is left alone.
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
    write: LockWrite,
    notes: &mut Notes,
) -> Result<bool> {
    if t.on_token.public_only {
        return Err(KmError::Unsupported(format!(
            "{t} is adopted publicOnly; deleting would remove only the public half"
        )));
    }
    let loc = &t.on_token.locator;
    // An expected identity is only required when there is something to delete.
    if let Some(h) = tok.find_key(t.object, loc, false)? {
        // Proven like `resolve`: If-Match must not pass on a public object beside another key.
        let got = compute_ids(t, tok, lock, h, plan_mode(t)?)?.ids;
        // --if-match names the primary scheme; otherwise the first scheme the lock records.
        let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
        let primary = t.schemes().into_iter().find(|s| got.contains_key(s.name()));
        let (scheme, expected) = match if_match {
            Some(want) => (primary, Some(want.to_owned())),
            None => t
                .schemes()
                .into_iter()
                .filter(|s| got.contains_key(s.name()))
                .find_map(|s| locked.and_then(|ids| ids.get(s.name())).map(|w| (Some(s), Some(w.clone()))))
                .unwrap_or((primary, None)),
        };
        let scheme = scheme.ok_or_else(|| KmError::Unsupported(format!("no identity computed for {t}")))?;
        let expected = expected
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {t}; pass --if-match")))?;
        if got.get(scheme.name()) != Some(&expected) {
            return Err(KmError::PreconditionFailed(format!(
                "{} holds {:?}, expected {expected}; not deleting",
                t,
                got.get(scheme.name())
            )));
        }
        let (n, left) = tok.destroy_identified(h, t.object, loc)?;
        notes.say(format!("destroyed {n} object(s) for {t}"));
        if left > 0 {
            notes
                .note(format_args!("left {left} public key object(s) under the locator of {t}: they hold another key"));
        }
    } else if !tok.logged_in && matches!(t.object.class, Class::PrivateKey | Class::SecretKey) {
        return Err(KmError::Unavailable(format!(
            "{t}: a session without login cannot see private objects, so it cannot tell the key is absent; \
             configure pinFile or pinEnv for token '{}'",
            t.token_name
        )));
    }
    let mut changed = false;
    if write == LockWrite::Record
        && let Some(m) = lock.realisations.get_mut(t.spec_name)
    {
        changed = m.remove(t.token_name).is_some();
        if m.is_empty() {
            lock.realisations.remove(t.spec_name);
        }
        changed |= lock.drop_unreferenced_observations();
    }
    Ok(changed)
}

/// The pseudo-FOD pre-use check of `reference` (`<object>` or `<object>.id.<scheme>`): pick the
/// (spec, token) pair and [`verify`] it, in a read-only session. Never writes: neither the lock,
/// nor the token, nor a TPM's persistent handles; an object that is not there is `NotFound`
/// (`cakeys create` makes it), one that is there but not locked fails with its `got:` (10).
/// A requested scheme must be one the spec computes on this token — refused (15) before the
/// token is opened, or before the object is looked for — and must itself be locked, not merely
/// computed beside another scheme that matched (10 with its `got:`). `open` opens the token.
///
/// # Errors
///
/// `Unsupported` (15) for a scheme the spec does not compute on this token; `HashMismatch`
/// (10) when a requested scheme is computed but not locked (its `got:` shows the computed
/// ID); plus `pick_spec`/`Target::new`/`verify` failures — the reference and the pair must
/// exist, and the realisation must compare clean.
pub fn check(
    cfg: &Config,
    reference: &str,
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
    reference: &str,
    spec: Option<&str>,
    token: Option<&str>,
    open: impl FnOnce(&str, hal::Access) -> Result<Token>,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(Resolved, Token)> {
    let (object, requested) = match reference.split_once(".id.") {
        Some((o, s)) => (o, Some(s)),
        None => (reference, None),
    };
    let (spec_name, token_name) = cfg.pick_spec(object, spec, token)?;
    let t = Target::new(cfg, &spec_name, &token_name)?;
    let names = |v: &[Scheme]| v.iter().map(|s| s.name()).collect::<Vec<_>>();
    // The schemes the spec can compute; an attestation scheme (§3.7) depends on the token's
    // provider, so only schemes_on below can tell whether this one computes it.
    let scheme = match requested {
        None => None,
        Some(name) => match Scheme::from_input(name) {
            Some(s) if (t.on_token.attestation && s.is_attestation()) || t.schemes().contains(&s) => Some(s),
            _ => {
                return Err(KmError::Unsupported(format!(
                    "scheme '{}' for '{object}'; it has {:?}{}",
                    Scheme::from_input(name).map_or(name, |s| s.name()),
                    names(&t.schemes()),
                    if t.on_token.attestation { " plus its token's attestation scheme" } else { "" }
                )));
            }
        },
    };
    let tok = open(&token_name, hal::Access::Read)?;
    if let Some(w) = tok.pin_warning() {
        notes.warn(w);
    }
    // The token may lack a mechanism the spec allows: refuse before the object is looked for.
    if let Some(s) = scheme {
        let on_token = schemes_on(&t, &tok)?;
        if !on_token.contains(&s) {
            return Err(KmError::Unsupported(format!(
                "scheme '{s}' for spec '{spec_name}' on '{token_name}'; it computes {:?}",
                names(&on_token)
            )));
        }
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
            return Err(KmError::HashMismatch {
                what: format!("'{object}' (scheme {s})"),
                expected: "<none>".into(),
                got: got.unwrap_or_default(),
            });
        }
    }
    Ok((r, tok))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;
    use std::path::Path;

    fn config(specs: &str) -> Config {
        let text = format!(
            "[tokens.a]\ntokenLabel = \"a\"\n[tokens.b]\ntokenLabel = \"b\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n{specs}"
        );
        cakeys_core::config::parse_config_with(&text, Path::new("keys.toml"), &|_| None).unwrap()
    }

    /// `create` naming no pair refuses (12), before any token is opened, what only the order of
    /// the run would decide: one object created by several specs on one token (with whose
    /// policy?), or on several tokens without `createOn` (where?). Naming the spec or the pair,
    /// `createOn`, or a lock that already pins the object settles it.
    #[test]
    fn create_refuses_births_the_order_of_the_run_would_decide() {
        let spec = |name: &str, tokens: &[&str], sign: bool| {
            let mut text = format!("\n[specs.{name}]\nobject = \"k\"\nattributes = {{ CKA_SIGN = {sign} }}\n");
            for t in tokens {
                let _ = writeln!(text, "tokens.{t} = {{ locator = {{ CKA_LABEL = \"k\" }} }}");
            }
            text
        };
        let never_open = |_: &str, _: &mut Notes| -> Result<Token> { panic!("a token was opened") };
        let refused = |cfg: &Config, s: Option<&str>, t: Option<&str>, why: &str| {
            let r = create_selected(
                cfg,
                s,
                t,
                &never_open,
                &mut Lock::default(),
                LockWrite::Compare,
                &mut Notes::default(),
            );
            let Err(e @ KmError::Ambiguous(_)) = r else { panic!("{s:?} {t:?}: not refused as ambiguous") };
            assert!(e.to_string().contains(why), "{e}");
        };
        let decided = |cfg: &Config, s: Option<&str>, t: Option<&str>, lock: &Lock| {
            let pairs = create_pairs(cfg, s, t).unwrap();
            unordered_births(cfg, &pairs, lock).unwrap_or_else(|e| panic!("{s:?} {t:?}: {e}"));
        };

        // Two specs on one token: whichever ran first would decide the key's policy.
        let two_specs = config(&(spec("k-sign", &["a"], true) + &spec("k-verify", &["a"], false)));
        refused(&two_specs, None, None, "on token 'a' by several specs (k-sign, k-verify)");
        refused(&two_specs, None, Some("a"), "by several specs");
        decided(&two_specs, Some("k-sign"), None, &Lock::default());

        // One spec on two tokens: each would get material of its own.
        let two_tokens = config(&spec("k", &["a", "b"], true));
        refused(&two_tokens, None, None, "on several tokens (a, b)");
        refused(&two_tokens, Some("k"), None, "name the one it is born on with createOn");
        decided(&two_tokens, None, Some("a"), &Lock::default());
        let mut born = config(&spec("k", &["a", "b"], true));
        born.create_on.insert("k".into(), "a".into());
        decided(&born, None, None, &Lock::default());

        // Pinned, the object is never created again, so nothing is left to decide.
        let mut pinned = Lock::default();
        pinned.objects.entry("k".into()).or_default().ids.insert("rfc7093m4".into(), "sha256-x".into());
        decided(&two_specs, None, None, &pinned);
        decided(&two_tokens, None, None, &pinned);
    }
}
