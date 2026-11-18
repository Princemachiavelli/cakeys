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

/// Whether a `pop-ecdh` proof derives into a sealed secret first (`Token::prove_ecdh`): the token
/// has HMAC to MAC with, and its module profile does not say it derives only extractable
/// (`derive.ecdh.sealed`, `derive_sealed`). `None` when that is not known (a plan from profiles
/// that do not decide HMAC).
#[must_use]
pub fn ecdh_seals(derive_sealed: Option<bool>, has_hmac: Option<bool>) -> Option<bool> {
    if derive_sealed == Some(false) { Some(false) } else { has_hmac }
}

/// The session keys a verb makes for `t`'s object in `mode`, each with cakeys' template
/// (`templates::session`), the provider's adjustment not yet asked: the secret its proof of
/// possession unwraps or derives (`pop-unwrap`, `pop-ecdh`), and its commitments' keys (the
/// `kw` input, wrap-rebind's KEK and copy). From an open token or from what is known without one:
/// `has` says whether the token implements a mechanism, `ecdh_seals` how a `pop-ecdh` proof
/// derives ([`ecdh_seals`]); `None`, not known, leaves out what depends on it, so a plan asks
/// only about what the run will make.
///
/// # Errors
///
/// `Unsupported` for a key type cakeys does not manage.
pub fn session_templates(
    t: &Target,
    mode: Mode,
    has: &dyn Fn(MechanismType) -> Option<bool>,
    ecdh_seals: Option<bool>,
) -> Result<Vec<(crate::SessionKey, Vec<cryptoki::object::Attribute>)>> {
    use crate::SessionKey;
    use crate::templates::{rebind_copy, session};
    let mut out = Vec::new();
    let proof = match cakeys_core::plan::expected_binding(t) {
        Some(b @ cakeys_core::config::Binding::PopUnwrap) => Some((b, true)),
        Some(b @ cakeys_core::config::Binding::PopEcdh) => ecdh_seals.map(|sealed| (b, sealed)),
        _ => None,
    };
    if let Some((binding, sealed)) = proof {
        let key = SessionKey::ProofSecret { binding, sealed };
        out.push((key, session(key)));
    }
    // The commitments the token implements, as `commits` picks them; none when that is not known.
    let usable: Option<Vec<Commit>> = wanted_commits(t, mode)
        .into_iter()
        .map(|c| has(hal::commit_mechanism(c)).map(|yes| yes.then_some(c)))
        .collect::<Option<Vec<_>>>()
        .map(|cs| cs.into_iter().flatten().collect());
    let Some(commits) = usable.filter(|cs| !cs.is_empty()) else { return Ok(out) };
    if mode == Mode::WrapRebind {
        out.push((SessionKey::RebindKek, session(SessionKey::RebindKek)));
        out.push((SessionKey::RebindCopy, rebind_copy(t.object, &commits)?));
    }
    if commits.contains(&Commit::Kw) {
        out.push((SessionKey::KwInput, session(SessionKey::KwInput)));
    }
    Ok(out)
}

/// Every template a verb sends for `t` on `tok` in `mode`, asked of the provider before anything
/// is made, since the proof and the commitments run only after the object exists (a key a module
/// cannot delete would stay): the generation's when `generating` from cakeys' own templates, and
/// [`session_templates`]. Only a refusal counts; the run asks again with what it sends.
///
/// # Errors
///
/// The provider's refusal; what building a template refuses (a size missing, a mechanism the
/// token does not offer).
fn check_templates(t: &Target, tok: &Token, mode: Mode, generating: bool) -> Result<()> {
    if generating {
        let on = crate::Declared::from(t);
        tok.generation_key(on)?;
        tok.generation_public(on, None)?;
    }
    for (key, template) in session_templates(t, mode, &|m| Some(tok.has(m)), Some(tok.ecdh_seals()))? {
        tok.provider.adjusted(&crate::Template::Session(key), template)?;
    }
    Ok(())
}

/// The capability check's template asks (`check_templates`) with no token, for a plan
/// (`gate::check`, camigrate's): the same templates, the policy's mechanism names mapped by the
/// profiles' dictionary (`templates::known_policy`), asked of `provider`. `Ok(Some(why))` when
/// the plan cannot build what the run will send (a vendor's mechanism name), so only the run
/// asks.
///
/// # Errors
///
/// The provider's refusal; what building a template refuses.
pub fn plan_templates(
    t: &Target,
    mode: Mode,
    generating: bool,
    provider: &dyn Provider,
    has: &dyn Fn(MechanismType) -> Option<bool>,
    ecdh_seals: Option<bool>,
) -> Result<Option<String>> {
    use crate::templates::{generation_key, generation_public, known_policy};
    use crate::{Declared, Half, Template};
    if generating {
        let on = Declared::from(t);
        let (Some(policy), Some(public_policy)) =
            (known_policy(&t.spec.attributes)?, known_policy(&t.spec.public_attributes)?)
        else {
            return Ok(Some(format!(
                "{t}: a mechanism its spec allows is none the profiles name, so provider '{}' is asked about its \
                 generation only when it runs",
                provider.name()
            )));
        };
        provider.adjusted(&Template::Generate(on, Half::Key), generation_key(on, policy)?)?;
        if let Some(public) = generation_public(on, public_policy, None)? {
            provider.adjusted(&Template::Generate(on, Half::Public), public)?;
        }
    }
    for (key, template) in session_templates(t, mode, has, ecdh_seals)? {
        provider.adjusted(&Template::Session(key), template)?;
    }
    Ok(None)
}

/// What an import into `tok` must pass before anything is created there: the capabilities `lock`
/// asks right after it ([`lock_import`]), the templates of its proof and commitments included.
/// camigrate's imports ask it first, so a refusal leaves nothing behind.
///
/// # Errors
///
/// What `lock`'s capability check refuses, the provider's templates included.
pub fn check_import(t: &Target, tok: &Token) -> Result<()> {
    check_imported_attestation(t, tok.provider.as_ref()).map_err(|m| tok.unsupported(m))?;
    check_capabilities(t, tok, plan_mode(t)?, Verb::Lock)
}

/// An attestation asked of a key about to be imported, which the provider attests only when the
/// device made the key (PIV): refused here, before the key is written, since a device such as a
/// `YubiKey` cannot delete what it imported. Every import path asks [`check_import`] before its
/// write; camigrate's plan asks this too.
///
/// # Errors
///
/// The refusal's text.
pub fn check_imported_attestation(
    t: &Target,
    provider: &dyn crate::provider::Provider,
) -> std::result::Result<(), String> {
    match provider.attestation() {
        Some(cap) if t.on_token.attestation && !cap.imported => Err(format!(
            "{t} asks for an attestation, and provider '{}' attests only keys the device generated, never an imported one",
            provider.name()
        )),
        _ => Ok(()),
    }
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
fn check_capabilities(t: &Target, tok: &Token, mode: Mode, verb: Verb) -> Result<()> {
    let creating = verb == Verb::Create;
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
    if let Some(b) = cakeys_core::plan::expected_binding(t) {
        tok.check_proof(t.object, b)?;
    }
    check_templates(t, tok, mode, own == Some(false))
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
pub fn resolve(t: &Target, tok: &Token, lock: &Lock) -> Result<Option<Resolved>> {
    resolve_with(t, tok, lock, Provision::Never)
}

fn resolve_with(t: &Target, tok: &Token, lock: &Lock, provision: Provision) -> Result<Option<Resolved>> {
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
    provision: Provision,
) -> Result<AttestationRecord> {
    let asymmetric = t.object.class.is_asymmetric();
    let spki = if asymmetric { Some(tok.spki(h, &t.on_token.locator)?) } else { None };
    let kind = scheme.attestation_kind().ok_or_else(|| {
        KmError::Unsupported(
            format!("provider '{}' advertises unknown attestation scheme {scheme}", tok.provider.name()).into(),
        )
    })?;
    let a = match tok.attest(h, t.object, spki.as_deref(), provision == Provision::IfMissing) {
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
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// What `t`'s run on its token demonstrated, as capability rows (docs/CAPROBE.md): the proof of
/// possession it gave, and the generation when it created the key (`created`). A run that
/// failed records nothing, so these are only ever yes.
fn answers(t: &Target, r: &Resolved, created: bool) -> std::collections::BTreeMap<String, Answered> {
    let mut out = std::collections::BTreeMap::new();
    if !t.object.class.is_asymmetric() {
        return out;
    }
    // The rows' own keys (`cakeys_profile::Capability`), as the gate reads them back.
    if let Some(proof) = r.binding.and_then(|b| crate::gate::proof_capability(t.object, b)) {
        out.insert(proof.to_string(), Answered::yes());
    }
    if created && let Some(generated) = crate::gate::generate_capability(t.object) {
        out.insert(generated.to_string(), Answered::yes());
    }
    out
}

/// What this run sees of `tok` (session, mechanisms, profile, module, token), and what `t`'s
/// run demonstrated ([`answers`]), for the lock to record or compare.
fn facts(t: &Target, tok: &Token, r: &Resolved, created: bool) -> Facts {
    Facts {
        observed: Observed { uri: r.uri.clone(), session: if tok.logged_in { Session::User } else { Session::Public } },
        observation: Observation {
            provider: Some(tok.provider.name().to_owned()),
            cakeys_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            profile: tok.profiles.module_name().map(str::to_owned),
            mechanisms: tok.mechanism_names(),
            module: Some(tok.module.clone()),
            token: Some(tok.token.clone()),
            capabilities: answers(t, r, created),
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
    let r = resolve(t, tok, lock)?.ok_or_else(|| absent(t))?;
    reconcile::compare(t, &r, lock, &facts(t, tok, &r, false), LockWrite::Compare, notes)?;
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
    let r = resolve_with(t, tok, lock, Provision::IfMissing)?.ok_or_else(|| absent(t))?;
    let facts = Facts { origin, ..facts(t, tok, &r, false) };
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
            format!("camigrate brings it from its file (camigrate import --token {} {})", t.token_name, t.object_name)
        }
        KeyOrigin::Adopt => "it is adopted, and nothing cakeys runs puts it there".to_owned(),
    };
    KmError::NotFound(format!("{t}: not under its locator; {what}").into())
}

/// Create `t`'s object, which `resolve` did not find, and resolve it. Refused before anything is
/// created when the lock pins the object (D1), a session without login cannot see the locator,
/// or anything sits under it; what was created is removed again when its identity cannot be
/// established.
fn create_absent(t: &Target, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<Resolved> {
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
    if let Some(note) = made_otherwise {
        notes.say(note.to_string());
    }
    let e = match resolve_with(t, tok, lock, Provision::IfMissing) {
        Ok(Some(r)) => return Ok(r),
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
    let r = create_absent(t, tok, lock, notes)?;
    let changed = reconcile::reconcile(t, &r, lock, &facts(t, tok, &r, true), write, notes)?;
    Ok(Made::Created(r, changed))
}

/// Why `create` never makes `t`'s object: its pair's origin is not `create`.
fn not_origin_create(t: &Target) -> Option<String> {
    match t.on_token.key_origin() {
        KeyOrigin::Create => None,
        KeyOrigin::Import => Some(format!(
            "origin = \"import\": camigrate brings its material here (camigrate migrate {} --to {}), never `create`",
            t.object_name, t.token_name
        )),
        KeyOrigin::Adopt => Some("origin = \"adopt\": it is found there, never created".into()),
        KeyOrigin::File => Some(format!(
            "origin = \"file\": camigrate brings its material here from the object's migrate.file \
             (camigrate import --token {} {}), never `create`",
            t.token_name, t.object_name
        )),
    }
}

/// Why `create` without a named pair leaves `t` alone: its origin is not `create`, or the lock
/// already pins its material (another token then needs that same material, which only
/// importing or migrating can put there).
fn not_created(t: &Target, lock: &Lock) -> Option<String> {
    not_origin_create(t).or_else(|| pinned(t, lock))
}

/// Why a pair's object is not created again: the lock already pins its material, so `create`
/// verifies the key that is there instead.
fn pinned(t: &Target, lock: &Lock) -> Option<String> {
    lock.objects.get(t.object_name).filter(|o| !o.ids.is_empty()).map(|_| {
        format!(
            "the lock already pins object '{}': the run verifies it is there and matches, as `check` \
             does, and makes nothing",
            t.object_name
        )
    })
}

/// Whether `create` would generate `t`'s object: its origin is `create` and the lock does not
/// pin it yet. What the static gate asks generation for.
#[must_use]
pub fn creates(t: &Target, lock: &Lock) -> bool {
    not_created(t, lock).is_none()
}

/// The (spec, token) pairs `create` selects, in config order: [`Config::select`], and a
/// selection naming a spec or an object that matches nothing is refused like the other verbs
/// refuse it.
///
/// # Errors
///
/// `Validation` (17), as [`Config::select`] and [`Config::address`].
pub fn create_pairs<'a>(
    cfg: &'a Config,
    object: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
) -> Result<Vec<(&'a str, &'a str)>> {
    let pairs = cfg.select(object, spec, token)?;
    if pairs.is_empty() && (object.is_some() || spec.is_some()) {
        cfg.address(object, spec, token)?;
    }
    Ok(pairs)
}

/// What `create` does with one selected pair ([`plan_create`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Created; a key already under the locator is `Exists` (19) when the run gets there.
    Create,
    /// The lock pins it: the run verifies the key that is there, as `check` does, and makes
    /// nothing ([`Made::Verified`]).
    Verify,
    /// Left alone: its origin is not `create`.
    Skip,
    /// The capability profiles say the token cannot make it.
    Refuse,
}

impl Action {
    /// The name `create --dry-run` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Verify => "verify",
            Action::Skip => "skip",
            Action::Refuse => "refuse",
        }
    }

    /// Whether the run opens the pair's token: to create it or to verify it.
    #[must_use]
    pub fn runs(self) -> bool {
        matches!(self, Action::Create | Action::Verify)
    }
}

/// One selected pair and what `create` does with it, decided before any token is opened.
pub struct Planned<'a> {
    /// The spec.
    pub spec: &'a str,
    /// The token.
    pub token: &'a str,
    /// The object the spec realises.
    pub object: &'a str,
    /// What `create` does with it.
    pub action: Action,
    /// Why: the skip's reason, the profiles' refusals, or what they leave undecided.
    pub reasons: Vec<String>,
}

/// What `create` does with each selected pair ([`create_pairs`]), decided from keys.toml, the
/// lock and the capability profiles alone, before any token is opened: a pair whose origin is
/// not `create` is skipped (unless the address names that one pair: an object or a spec, and a
/// token); one whose object the lock pins is verified, never made again; every other pair goes
/// through the static gate ([`crate::gate::check`]), whose *no* refuses it and whose *unknown*
/// is a reason to try. A token whose profiles are not known without opening it is not gated
/// here; the live check still refuses before generating.
///
/// # Errors
///
/// [`create_pairs`]' refusals; `Validation` (17) for a named pair whose origin is not
/// `create`, or a spec `plan_mode` refuses; the gate's own errors.
pub fn plan_create<'a>(
    cfg: &'a Config,
    object: Option<&str>,
    spec: Option<&str>,
    token: Option<&str>,
    lock: &Lock,
    registry: &Registry,
) -> Result<Vec<Planned<'a>>> {
    let pairs = create_pairs(cfg, object, spec, token)?;
    let named = token.is_some() && (object.is_some() || spec.is_some()) && pairs.len() == 1;
    let mut stacks = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    for (spec_name, token_name) in pairs {
        let t = Target::new(cfg, spec_name, token_name)?;
        let planned =
            |action, reasons| Planned { spec: spec_name, token: token_name, object: t.object_name, action, reasons };
        let mode = plan_mode(&t)?;
        if let Some(why) = not_origin_create(&t) {
            if named {
                return Err(KmError::Validation(format!("{t}: {why}").into()));
            }
            out.push(planned(Action::Skip, vec![why]));
            continue;
        }
        let (action, why) = match pinned(&t, lock) {
            Some(why) => (Action::Verify, vec![why]),
            None => (Action::Create, Vec::new()),
        };
        if !stacks.contains_key(token_name) {
            let token_cfg = &cfg.tokens[token_name];
            stacks.insert(token_name, crate::gate::stack(token_name, token_cfg, lock)?);
        }
        out.push(match &stacks[token_name] {
            Ok(stack) => {
                let v = crate::gate::check(&t, mode, stack, registry, creates(&t, lock))?;
                if v.refusals.is_empty() {
                    planned(action, [why, v.notes].concat())
                } else {
                    planned(Action::Refuse, v.refusals)
                }
            }
            Err(e) => planned(action, [why, vec![format!("{t}: not checked before opening the token: {e}")]].concat()),
        });
    }
    Ok(out)
}

/// What [`create_selected`] did.
pub struct Created {
    /// The realised objects, in the order they were created.
    pub created: Vec<Resolved>,
    /// Whether the lock changed and `persist` saved it.
    pub changed: bool,
    /// The failure that ended the run, if any.
    pub failed: Option<KmError>,
}

/// The `create` verb: [`create`] over each of `pairs` (what [`plan_create`] decided to create or
/// verify), in order. Every step of a pair, opening its token included, ends the run there,
/// reported in [`Created::failed`] beside what was created before; a verified key is said in a
/// note. Each pair that changed `lock` is `persist`ed before the next pair is touched, so a run
/// killed or failing later never leaves a key on a token the lock file does not record; a
/// failed save ends the run as a pair's failure does.
///
/// At most one token is open at a time: each is closed before the next opens.
///
/// # Errors
///
/// None of its own: a pair's failure, or its record's, is [`Created::failed`].
pub fn create_selected(
    cfg: &Config,
    pairs: &[(&str, &str)],
    open: &dyn Fn(&str, &mut Notes) -> Result<Token>,
    lock: &mut Lock,
    write: LockWrite,
    persist: &mut dyn FnMut(&Lock) -> Result<()>,
    notes: &mut Notes,
) -> Created {
    let mut out = Created { created: Vec::new(), changed: false, failed: None };
    let mut current: Option<Token> = None;
    for &(spec_name, token_name) in pairs {
        let mut pair = || -> Result<Made> {
            let t = Target::new(cfg, spec_name, token_name)?;
            // Another token's module is finalized (dropped) before the next open.
            let tok = match current.take().filter(|tok| tok.name == token_name) {
                Some(tok) => current.insert(tok),
                None => current.insert(open(token_name, notes)?),
            };
            create(&t, tok, lock, write, notes)
        };
        match pair() {
            Ok(Made::Created(r, c)) => {
                let saved = if c { persist(lock) } else { Ok(()) };
                out.created.push(r);
                if let Err(e) = saved {
                    notes.say(format!(
                        "'{spec_name}' on token '{token_name}' was created, but the lock could not record it"
                    ));
                    out.failed = Some(e);
                    break;
                }
                out.changed |= c;
            }
            Ok(Made::Verified(_)) => {}
            Err(e) => {
                out.failed = Some(e);
                break;
            }
        }
    }
    out
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
        return Err(KmError::Unsupported(
            format!("{t} is adopted publicOnly; deleting would remove only the public half").into(),
        ));
    }
    let loc = &t.on_token.locator;
    // An expected identity is only required when there is something to delete.
    if let Some(h) = tok.find_key(t.object, loc, false)? {
        // Proven like `resolve`: If-Match must not pass on a public object beside another key.
        let got = compute_ids(t, tok, lock, h, plan_mode(t)?)?.ids;
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
        let (n, left) = tok.destroy_identified(h, t.object, loc)?;
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
    let names = |v: &[Scheme]| v.iter().map(|s| s.name()).collect::<Vec<_>>();
    // The schemes the spec can compute; an attestation scheme (§3.7) depends on the token's
    // provider, so only schemes_on below can tell whether this one computes it.
    let scheme = match requested {
        None => None,
        Some(name) => match Scheme::from_input(name) {
            Some(s) if (t.on_token.attestation && s.is_attestation()) || t.schemes().contains(&s) => Some(s),
            _ => {
                return Err(KmError::Unsupported(
                    format!(
                        "scheme '{}' for '{object}'; it has {:?}{}",
                        Scheme::from_input(name).map_or(name, |s| s.name()),
                        names(&t.schemes()),
                        if t.on_token.attestation { " plus its token's attestation scheme" } else { "" }
                    )
                    .into(),
                ));
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
            return Err(KmError::Unsupported(
                format!("scheme '{s}' for spec '{spec_name}' on '{token_name}'; it computes {:?}", names(&on_token))
                    .into(),
            ));
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
            return Err(KmError::FirstUse { what: format!("'{object}' (scheme {s})"), got: got.unwrap_or_default() });
        }
    }
    Ok((r, tok))
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
