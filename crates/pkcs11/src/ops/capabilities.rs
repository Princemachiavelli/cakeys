//! The checks of what a pair needs from its token, made before anything is written: the
//! mechanisms that its identity and its attestation use, the templates that the token accepts,
//! and the checks before an import.

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// What a target needs from its token, independent of which token it is. Both the live check
/// before anything is created (`check_capabilities`) and the static gate against the capability
/// profiles ([`crate::gate::check`], docs/CAPROBE.md) take their list of needs from this struct,
/// so the two checks cannot disagree.
pub struct Needs {
    /// The mechanism groups, in the order in which they are checked. The token must implement at
    /// least one mechanism of each group.
    pub groups: Vec<Vec<MechanismType>>,
    /// The mechanism that generates the object, which `create` also needs. The token must also be
    /// able to generate the object's key type, curve and size. `None` when the verb does not
    /// create the object.
    pub generation: Option<MechanismType>,
}

/// Returns whether the object of `t`, when it is created, is generated from the module's own
/// template ([`Provider::generation`]). When the provider could not make the key as it is
/// declared, the provider's refusal is returned as the error, before anything is created.
///
/// # Errors
///
/// The provider's refusal.
pub fn own_generation(t: &Target, provider: &dyn Provider) -> Result<bool> {
    let binding = cakeys_core::plan::expected_binding(t);
    Ok(provider.generation(t.object, t.spec, &t.on_token.locator, binding)?.is_some())
}

/// Returns whether a `pop-ecdh` proof first derives the shared secret into a sealed secret key
/// (`Token::prove_ecdh`). That is the case when the token has HMAC to compute a MAC with, and the
/// module profile does not say that the module derives only extractable keys
/// (`derive.ecdh.sealed`, passed as `derive_sealed`). Returns `None` when that is not known, for
/// example in a plan from profiles that do not decide HMAC.
#[must_use]
pub fn ecdh_seals(derive_sealed: Option<bool>, has_hmac: Option<bool>) -> Option<bool> {
    if derive_sealed == Some(false) { Some(false) } else { has_hmac }
}

/// Returns the session keys that a verb makes for the object of `t` in `mode`, each with cakeys'
/// template (`templates::session`) before the provider adjusts it. The session keys are the
/// secret that the proof of possession unwraps or derives (`pop-unwrap`, `pop-ecdh`) and the keys
/// of the commitments (the `kw` input, and the KEK and the copy of `Mode::WrapRebind`).
///
/// The inputs come from an open token or from what is known without one: `has` says whether the
/// token implements a mechanism, and `ecdh_seals` says how a `pop-ecdh` proof derives
/// ([`ecdh_seals`]). When an input is `None` (not known), the function leaves out the templates
/// that depend on it, so that a plan asks only about what the run will make.
///
/// # Errors
///
/// `Unsupported` for a key type that cakeys does not manage.
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
    // The commitments that the token implements, chosen as `commits` chooses them. When `has`
    // does not know one of the mechanisms, `usable` is `None`, and no commitment template is
    // returned.
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

/// Asks the provider about every template that a verb sends for `t` on `tok` in `mode`, before
/// anything is made. The check must come first, because the proof and the commitments run only
/// after the object exists, and a key on a module that cannot delete keys would stay there after
/// a later refusal. The templates are the generation's templates, when `generating` from cakeys'
/// own templates, and the templates of [`session_templates`]. Only a refusal matters here,
/// because the run asks the provider again with the templates that it actually sends.
///
/// # Errors
///
/// The provider's refusal, and the error when a template cannot be built (a missing size, or a
/// mechanism that the token does not offer).
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

/// Asks `provider` about the same templates as `check_templates`, but without a token, for a plan
/// (`gate::check`, and camigrate's plan). The mechanism names in the policy are mapped through the
/// profiles' dictionary (`templates::known_policy`). Returns `Ok(Some(why))` when the plan cannot
/// build what the run will send (for example, because the policy names a vendor's mechanism), so
/// that only the run asks the provider.
///
/// # Errors
///
/// The provider's refusal, and the error when a template cannot be built.
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

/// Checks what an import into `tok` must pass before anything is created there. These are the
/// capabilities that `lock` checks right after the import ([`lock_import`]), including the
/// templates of the proof and of the commitments. camigrate's imports call this function first,
/// so that a refusal leaves nothing behind on the token.
///
/// # Errors
///
/// Every refusal of the capability check of `lock`, including the provider's refusal of a
/// template. `Validation` (exit 17) for a key that the module cannot place under its locator
/// (`Provider::placement`).
pub fn check_import(t: &Target, tok: &Token) -> Result<()> {
    // `check_capabilities` checks the static rules (`static_rules`) first. The placement rule
    // checks, before the write, where the module can place the key (on ykcs11, a PIV slot chosen
    // by `CKA_ID`, and never slot f9, which holds the attestation key), because a key imported
    // into a PIV slot cannot be erased (review 2026-11-23 B-3). The imported-attestation rule
    // refuses an attestation of an imported key.
    check_capabilities(t, tok, plan_mode(t)?, Verb::Import)
}

/// Refuses an attestation that is requested for a key about to be imported, when the provider
/// attests only keys that the device generated (PIV). The refusal happens here, before the key is
/// written, because a device such as a `YubiKey` cannot delete a key that it imported. Every
/// import path calls [`check_import`] before its write, and camigrate's plan also calls this
/// function.
///
/// # Errors
///
/// The text of the refusal.
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

/// Returns the [`Needs`] of `t` in `mode`. `creating` is `Some` when `create` makes the object,
/// and it then holds the result of [`own_generation`]: whether the module generates the object
/// from its own template, which may make what a standard template cannot. `creating` is `None`
/// for every other verb, because those verbs find an object that is already there.
///
/// # Errors
///
/// `Unsupported` for a key type that cakeys does not manage.
pub fn needs(t: &Target, mode: Mode, creating: Option<bool>) -> Result<Needs> {
    let mut groups = Vec::new();
    // The commitments come first, because a token that implements none of them gives the most
    // useful refusal.
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
            // An HMAC key type that is bound to a hash is generated with its own
            // `CKM_SHA*_KEY_GEN` mechanism, unless the module generates it in its own way
            // (libkmsp11).
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

/// Returns the refusal message for a mechanism group that the token lacks.
fn lacking(token: &str, group: &[MechanismType], mode: Mode, t: &Target) -> String {
    if let [m] = group {
        return format!("token '{token}' lacks {m} needed for mode '{mode}' of {t}");
    }
    let names: Vec<String> = group.iter().map(ToString::to_string).collect();
    format!("token '{token}' implements none of {} needed for mode '{mode}' of {t}", names.join(", "))
}

/// Refuses an attestation that the provider cannot compute, before anything is written (the
/// caller turns the text into exit 15), in the same way as a scheme that the token lacks. The
/// attestation is refused early because it is part of the identity that the realisation must
/// provide from then on.
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

/// Checks what `t` in `mode` needs from the open token `tok` for the write `verb`, before anything
/// is created. It first checks the static rules with the token's provider ([`static_rules`]:
/// placement, the attestation, and the module's own generation). It then checks what the token
/// itself can do: the mechanisms, the generation, the proof, and the templates that the write
/// sends.
///
/// # Errors
///
/// The first refusal, which names its rule ([`KmError::rule`]).
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
    // Check the proof of possession that the realisation will make, as the spec declares it.
    // camigrate's plan checks the same proof.
    if let Some(b) = cakeys_core::plan::expected_binding(t) {
        tok.check_proof(t.object, b).map_err(capability)?;
    }
    check_templates(t, tok, mode, own == Some(false)).map_err(|e| e.with_rule(Rule::Templates))
}
