//! What a pair needs of its token, checked before anything is written: the mechanisms its
//! identity and attestation take, the templates the token accepts, and an import's checks.

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

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
) -> Result<Vec<crate::templates::SessionTemplate>> {
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
        out.push(session(key));
    }
    // The commitments the token implements, as `commits` picks them; none when that is not known.
    let usable: Option<Vec<Commit>> = wanted_commits(t, mode)
        .into_iter()
        .map(|c| has(hal::commit_mechanism(c)).map(|yes| yes.then_some(c)))
        .collect::<Option<Vec<_>>>()
        .map(|cs| cs.into_iter().flatten().collect());
    let Some(commits) = usable.filter(|cs| !cs.is_empty()) else { return Ok(out) };
    if mode == Mode::WrapRebind {
        out.push(session(SessionKey::RebindKek));
        out.push(rebind_copy(t.object, &commits)?);
    }
    if commits.contains(&Commit::Kw) {
        out.push(session(SessionKey::KwInput));
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
    for template in session_templates(t, mode, &|m| Some(tok.has(m)), Some(tok.ecdh_seals()))? {
        tok.provider.adjusted_session(template)?;
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
    for template in session_templates(t, mode, has, ecdh_seals)? {
        provider.adjusted_session(template)?;
    }
    Ok(None)
}

/// What an import into `tok` must pass before anything is created there: the capabilities `lock`
/// asks right after it ([`lock_import`]), the templates of its proof and commitments included.
/// camigrate's imports ask it first, so a refusal leaves nothing behind.
///
/// # Errors
///
/// What `lock`'s capability check refuses, the provider's templates included; `Validation` (17)
/// for a key the module cannot place under its locator (`Provider::placement`).
pub fn check_import(t: &Target, tok: &Token) -> Result<()> {
    // The static rules first (`static_rules`): where the module can place it (ykcs11: a PIV slot
    // by CKA_ID, never f9's attestation key), before the write, since a PIV slot's imported key
    // cannot be erased (review 2026-11-23 B-3); an attestation of an imported key.
    check_capabilities(t, tok, plan_mode(t)?, Verb::Import)
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

/// What `t` in `mode` needs of the open token `tok` before the write `verb`, checked before
/// anything is created: the static rules with the token's provider ([`static_rules`]: placement,
/// the attestation, the module's own generation), then what the token itself can do, the
/// mechanisms, the generation, the proof and the templates it sends.
///
/// # Errors
///
/// The first refusal, naming its rule ([`KmError::rule`]).
pub(super) fn check_capabilities(t: &Target, tok: &Token, mode: Mode, verb: Verb) -> Result<()> {
    let own = static_rules(t, mode, Seat::Resolved(tok.provider.as_ref()), verb, None)?.first()?.own;
    let capability = |e: KmError| e.with_rule(Rule::Capability);
    let needs = needs(t, mode, own).map_err(|e| capability(tok.provider.hinted(Topic::Generate, e)))?;
    let generation = needs.generation.map(|m| vec![m]);
    if let Some(g) = needs.groups.iter().chain(&generation).find(|g| !g.iter().any(|m| tok.has(*m))) {
        let about = if generation.as_ref().is_some_and(|own| std::ptr::eq(own, g)) {
            Topic::Generate
        } else {
            Topic::Mechanism
        };
        return Err(capability(tok.unsupported_for(about, lacking(&tok.name, g, mode, t))));
    }
    // The proof the realisation will make, as the spec says it (camigrate's plan asks the same).
    if let Some(b) = cakeys_core::plan::expected_binding(t) {
        tok.check_proof(t.object, b).map_err(capability)?;
    }
    check_templates(t, tok, mode, own == Some(false)).map_err(|e| e.with_rule(Rule::Templates))
}
