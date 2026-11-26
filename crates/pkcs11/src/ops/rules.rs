//! The rules that a pair must pass before anything is written. Each rule has a name ([`Rule`]).
//! A rule that refuses a pair returns a [`Refusal`] that names the rule. A rule that only the
//! write can decide returns a [`Deferred`] that names the rule, so that a rule is never passed
//! without a decision.
//!
//! [`static_rules`] holds the rules that are decided without a token. Every entry path calls this
//! one function: the static gate (`validate`, the plan of `create`, and [`crate::gate::check`])
//! and the live checks before a write ([`check_capabilities`], [`check_import`], and
//! `Token::create` for placement). As a result, no path can skip a rule (review 2026-11-24 B-1,
//! B-2; docs/archive/REVIEW-2026-11-24/phase1-design.md §1.3).

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use crate::resolution::Resolved as Profiles;
use cakeys_core::config::ObjectCfg;
use cakeys_profile::{Capability, Effective, On, Set, Verdict};

/// The rules. Each rule has one name, and refusals, deferrals and the JSON rows all use that
/// name. The enum is defined in `cakeys_core` next to [`cakeys_core::Check`], so that the `Reason`
/// of a refusal can name its rule.
pub use cakeys_core::Rule;

/// A rule's refusal of a pair. It holds the error that the run ends with, and that error carries
/// the rule's name ([`KmError::rule`]). The exit code of the run is the exit code of the error.
#[derive(Debug)]
pub struct Refusal {
    /// The rule that refused.
    pub rule: Rule,
    /// The reason for the refusal, as the run reports it.
    pub error: KmError,
}

impl Refusal {
    /// Returns the refusal of `rule` with `error`, and adds the name of `rule` to `error`.
    #[must_use]
    pub fn new(rule: Rule, error: KmError) -> Refusal {
        Refusal { rule, error: error.with_rule(rule) }
    }
}

impl From<Refusal> for KmError {
    fn from(r: Refusal) -> KmError {
        r.error
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

/// A rule that a plan could not decide, and the reason. Only the write can decide such a rule,
/// for example because the provider is known only when the token is opened, or because the
/// profiles give no answer. A deferred rule is never treated as passed, because the run checks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    /// The rule.
    pub rule: Rule,
    /// The reason why the rule is not decided here. The text starts with the pair that it is
    /// about.
    pub why: String,
}

impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (deferred: {})", self.why, self.rule)
    }
}

/// Formats `deferred` as lines, with one line for each distinct reason (and each reason starts
/// with its pair): `<why> (deferred: <rule>, <rule>)`. The rules on a line are in the order in
/// which they were deferred.
#[must_use]
pub fn deferred_lines(deferred: &[Deferred]) -> Vec<String> {
    let mut lines: Vec<(&str, Vec<&str>)> = Vec::new();
    for d in deferred {
        match lines.iter_mut().find(|(why, _)| *why == d.why) {
            Some((_, rules)) => rules.push(d.rule.name()),
            None => lines.push((&d.why, vec![d.rule.name()])),
        }
    }
    lines.into_iter().map(|(why, rules)| format!("{why} (deferred: {})", rules.join(", "))).collect()
}

/// The provider that a plan checks against: either the provider that will run the write, or the
/// reason why that provider is not known yet. When the provider is not known, the plan defers
/// every provider rule that applies, and it never skips one.
pub enum Seat<'a> {
    /// The provider that the write runs with.
    Resolved(&'a dyn Provider),
    /// The provider is not known until the token is opened, because the token entry names no
    /// `provider` and the lock records none, or because it names a provider that this build does
    /// not include. The string is the reason.
    Unresolved(String),
}

/// The write that a plan is for. The verb decides which rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `create` generates the object.
    Create,
    /// An import (camigrate) puts the material on the token.
    Import,
    /// The object is already on the token: `lock` records it, and `create` verifies it.
    Lock,
}

impl Verb {
    /// Returns the verb that the pair of `t` needs, given `lock`. The verb is `Create` when the
    /// origin is `create` and the lock does not record the object ([`creates`]). It is `Import`
    /// when the origin is `import` or `file`, because camigrate imports the object. In every other
    /// case, it is `Lock`, because the object is expected to be on the token already.
    #[must_use]
    pub fn of(t: &Target, lock: &Lock) -> Verb {
        match t.on_token.key_origin() {
            _ if creates(t, lock) => Verb::Create,
            KeyOrigin::Import | KeyOrigin::File => Verb::Import,
            KeyOrigin::Create | KeyOrigin::Adopt => Verb::Lock,
        }
    }
}

/// The result of [`static_rules`] for a pair.
#[derive(Debug, Default)]
pub struct Verdicts {
    /// The reasons why the pair cannot be realised, each with its rule.
    pub refusals: Vec<Refusal>,
    /// The rules that only the write can decide.
    pub deferred: Vec<Deferred>,
    /// Whether a created key is generated from the module's own template ([`own_generation`]).
    /// It is `None` when the plan did not decide it, because the verb is not `Create` or the
    /// provider is not known.
    pub(crate) own: Option<bool>,
}

impl Verdicts {
    fn refuse(mut self, rule: Rule, error: KmError) -> Verdicts {
        self.refusals.push(Refusal::new(rule, error));
        self
    }

    fn defer(&mut self, rule: Rule, why: String) {
        self.deferred.push(Deferred { rule, why });
    }

    /// Returns the verdicts unchanged when there is no refusal.
    ///
    /// # Errors
    ///
    /// The first refusal, as the error that a run ends with.
    pub fn first(self) -> Result<Verdicts> {
        let Verdicts { mut refusals, deferred, own } = self;
        if refusals.is_empty() {
            return Ok(Verdicts { refusals, deferred, own });
        }
        Err(refusals.swap_remove(0).into())
    }
}

/// Checks the rules of `t` that need the open token, in the order in which the write checks them.
/// The plan checks them (`create --dry-run`, on the token opened read-only, [`plan_on_tokens`]),
/// and the write checks them again just before it writes ([`create`]). Both use this function,
/// so a change on the token between the plan and the write is caught in the same way.
///
/// For a creation (`verb` is [`Verb::Create`]), the rules are, in this order:
///
/// - a key under the locator that the lock does not record (`unpinned-exists`, exit 19). A key
///   that the lock records is verified instead, and no rule decides that case;
/// - what the open token lists (`check_capabilities`, each refusal with its rule);
/// - a session without login when the object needs a login to be seen (`needs-login`, exit 16);
/// - material that the lock records and the token lost, which a new generation could never match
///   (`pinned-lost`, exit 14, D1);
/// - any session without login, because it cannot see a private object of another class under
///   the locator (exit 16);
/// - any object under the locator (`locator-free`, exit 13).
///
/// The first refusal ends the checks, as it ends the write. An import and a lock check their own
/// rules (camigrate's `free_locator`, and the compare of `lock`), so this function returns no
/// refusal for them (review 2026-11-24 C-4).
///
/// # Errors
///
/// A failure that belongs to no rule: a failure of the module (exit 16), several keys under the
/// locator (exit 12), or an error that a check raised without naming its rule.
pub fn token_rules(t: &Target, tok: &Token, lock: &Lock, verb: Verb) -> Result<Vec<Refusal>> {
    if verb != Verb::Create {
        return Ok(Vec::new());
    }
    let loc = &t.on_token.locator;
    if tok.find_key(&t.object, loc, false)?.is_some() {
        if pinned(t, lock).is_some() {
            return Ok(Vec::new());
        }
        let e = KmError::Exists(
            format!("{t} is already under its locator: nothing was created; `cakeys lock` records a key that is there")
                .into(),
        );
        return Ok(vec![Refusal::new(Rule::UnpinnedExists, e)]);
    }
    // A check's error becomes the refusal of the rule that the error names. An error that names
    // no rule is returned as an error, not as a refusal.
    let refused = |r: Result<()>| match r {
        Ok(()) => Ok(None),
        Err(e) => match e.rule() {
            Some(rule) => Ok(Some(Refusal { rule, error: e })),
            None => Err(e),
        },
    };
    if let Some(r) = refused(check_capabilities(t, tok, plan_mode(t)?, Verb::Create))? {
        return Ok(vec![r]);
    }
    // If-None-Match: never create over any other object under the locator. On a PIV token, a
    // generation into an occupied slot would silently replace the slot's key. A session without
    // login sees no private object, so it cannot tell whether the locator is free. It also cannot
    // tell whether a private or secret key that the lock records is gone, which the D1 check
    // below would report.
    let free = "the locator is free";
    if let Some(r) = refused(needs_login(t, tok, lock, free))? {
        return Ok(vec![r]);
    }
    // D1: the lock already records this object's material, so a new generation can only end in
    // a mismatch. If this token held the same material, `find_key` would have found it above.
    if let Some(ids) = lock.objects.get(t.object_name).map(|o| &o.ids).filter(|ids| !ids.is_empty()) {
        let e = KmError::PreconditionFailed(Reason::rule(
            Rule::PinnedLost,
            format!(
                "{t}: the lock already pins object '{}' ({}); creating it would generate different material that \
                 can never match; put the same material under the locator, or give this token's key its own object \
                 name",
                t.object_name,
                ids.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
            ),
        ));
        return Ok(vec![Refusal::new(Rule::PinnedLost, e)]);
    }
    // Whatever the object's class is, an object of another class under the locator may be
    // private, and a session without login cannot see it.
    if !tok.logged_in {
        let e = KmError::Unavailable(
            format!(
                "{t}: a session without login cannot see private objects, so it cannot tell {free}; configure \
                 pinFile or pinEnv for token '{}'",
                t.token_name
            )
            .into(),
        );
        return Ok(vec![Refusal::new(Rule::NeedsLogin, e)]);
    }
    // Objects of every class count here, unlike for an import (`Token::occupied`). A certificate
    // that is already under the locator certifies some other key, and never the key that is
    // generated now.
    let present = tok.find_any(loc)?;
    if !present.is_empty() {
        let e = KmError::Conflict(Reason::rule(
            Rule::LocatorFree,
            format!(
                "{} objects of another class already sit under the locator of {t}; refusing to create",
                present.len()
            ),
        ));
        return Ok(vec![Refusal::new(Rule::LocatorFree, e)]);
    }
    Ok(Vec::new())
}

/// Refuses with exit 16 when the session has no login and the object of `t` needs a login to be
/// seen ([`Target::needs_login`]). Callers call this function when the object was not found,
/// because such a session must never report the object as absent or the locator as free (review
/// 2026-11-24 B-4). `cannot` names what the session cannot tell, for the message.
///
/// # Errors
///
/// `Unavailable` (exit 16), which names the `needs-login` rule, for a session without login.
pub(crate) fn needs_login(t: &Target, tok: &Token, lock: &Lock, cannot: &str) -> Result<()> {
    if tok.logged_in || !t.needs_login(lock) {
        return Ok(());
    }
    let e = KmError::Unavailable(
        format!(
            "{t}: a session without login cannot see private objects, so it cannot tell {cannot}; configure \
             pinFile or pinEnv for token '{}'",
            t.token_name
        )
        .into(),
    );
    Err(Refusal::new(Rule::NeedsLogin, e).into())
}

/// Checks whether a key may be created under `loc` on the module of `provider`
/// ([`Provider::placement`]). This is the only place where that check is made, both for a pair's
/// key ([`static_rules`]) and for every creation (`Token::create`). An object that is not a key
/// always passes.
///
/// # Errors
///
/// The provider's refusal (exit 17), which names the `placement` rule.
pub(crate) fn placement(provider: &dyn Provider, class: Class, loc: &cakeys_core::config::Locator) -> Result<()> {
    if !class.is_key() {
        return Ok(());
    }
    provider.placement(loc).map_err(|e| Refusal::new(Rule::Placement, e).into())
}

/// Checks whether the module of `provider` removes an object of `class` under `loc`
/// ([`Provider::deletion`]). This is the only place where that check is made, both for the plan
/// of `delete` and for every destroy (`Token::destroy_handles`).
///
/// # Errors
///
/// The provider's refusal (exit 15), which names the `delete-refused` rule.
pub(crate) fn deletion(provider: &dyn Provider, class: Class, loc: &cakeys_core::config::Locator) -> Result<()> {
    provider.deletion(class, loc).map_err(|e| Refusal::new(Rule::DeleteRefused, e).into())
}

/// Checks whether `tok` removes the object of `t` when asked. The check runs before anything is
/// looked up again or destroyed, so that `delete --dry-run` reports what `delete` would do
/// (review 2026-11-24 B-13). The function refuses when the module profile's `delete.<class>` row
/// answers no, which means that caprobe measured that `C_DestroyObject` left objects of that class
/// behind. It also refuses when the provider refuses ([`Provider::deletion`]). A missing row
/// decides nothing: the delete is tried, and the lookup after it (`Token::destroy_handles`)
/// reports what is still there.
///
/// # Errors
///
/// `Unsupported` (exit 15, `delete-refused`), which names the profile row and its evidence, or
/// the provider's refusal.
pub(crate) fn delete_refused(t: &Target, tok: &crate::Token) -> Result<()> {
    let class = t.object.class;
    let row = cakeys_profile::Capability::Delete(class.to_string());
    if let Some(m) = tok.profiles.module.as_ref()
        && m.answer(&row) == Some(false)
    {
        let why = m.evidence(&row, "").map_or_else(String::new, |e| format!(": {e}"));
        let refusal = format!(
            "{t}: token '{}' does not remove a {class} when asked ({} says {row} = no{why}); remove it with the \
             module's own tools, then `cakeys delete` finds it absent",
            t.token_name, m.profile
        );
        return Err(Refusal::new(Rule::DeleteRefused, KmError::Unsupported(refusal.into())).into());
    }
    deletion(tok.provider.as_ref(), class, &t.on_token.locator)
        .map_err(|e| e.prefixed(format_args!("{t}: deleting {class} on '{}'", t.token_name)))
}

/// Checks the rules of `t` in `mode` that can be decided without a token, for the write `verb`.
/// The provider in `seat` decides the provider rules. When `profiles` is given (the token's
/// profile stack, as the static gate resolves it), the capability profiles decide the capability
/// rules. The rules are:
///
/// - placement, for a key that the write puts on the token (`create` generates the key, or an
///   import puts it there). `lock` puts no key on the token;
/// - attestation cover, when the spec opts into an attestation;
/// - imported attestation, when the key is imported;
/// - own generation, when `create` generates the key;
/// - with `profiles`: the templates that the write sends, the mechanisms, the proof, the
///   generation, and a secret key's commitments. A *no* in a profile refuses the pair, and an
///   *unknown* is deferred to the open token.
///
/// A refusal that makes the other rules meaningless (placement, own generation, or a key type
/// that cakeys does not manage) is returned as the only refusal. When the provider is not known
/// (`Seat::Unresolved`), each provider rule that applies is deferred, and when `profiles` is also
/// missing, the capability rule is deferred too. When `profiles` is missing but the provider is
/// known, the open token decides the capability rules right after the plan (the live check).
///
/// # Errors
///
/// `Validation` (exit 17) when no profile set is active.
pub fn static_rules(t: &Target, mode: Mode, seat: Seat, verb: Verb, profiles: Option<&Profiles>) -> Result<Verdicts> {
    let mut out = Verdicts::default();
    let (creating, imported) = (verb == Verb::Create, verb == Verb::Import);
    let placed = t.object.class.is_key() && (creating || imported);
    let provider = match seat {
        Seat::Resolved(p) => Some(p),
        Seat::Unresolved(why) => {
            // When `profiles` is also missing, what the token can do is known only when the token
            // is opened, so the capability rule is deferred too.
            let rules = [
                (placed, Rule::Placement),
                (t.on_token.attestation, Rule::AttestationCover),
                (t.on_token.attestation && imported, Rule::ImportedAttestation),
                (creating, Rule::OwnGeneration),
                (true, Rule::Templates),
                (profiles.is_none(), Rule::Capability),
            ];
            for (_, rule) in rules.into_iter().filter(|(applies, _)| *applies) {
                out.defer(rule, format!("{t}: {why}"));
            }
            None
        }
    };
    if let Some(p) = provider {
        if placed && let Err(e) = placement(p, t.object.class, &t.on_token.locator) {
            return Ok(out.refuse(Rule::Placement, e.prefixed(format_args!("{t}: provider '{}'", p.name()))));
        }
        if creating {
            match own_generation(t, p) {
                Ok(own) => out.own = Some(own),
                Err(e) => return Ok(out.refuse(Rule::OwnGeneration, p.hinted(Topic::Generate, e))),
            }
        }
        if let Err(m) = check_attestation(t, p) {
            out = out.refuse(Rule::AttestationCover, KmError::Unsupported(m.into()));
        }
        if imported && let Err(m) = check_imported_attestation(t, p) {
            out = out.refuse(Rule::ImportedAttestation, KmError::Unsupported(m.into()));
        }
    }
    let Some(profiles) = profiles else { return Ok(out) };
    // `out.own` is set only when the provider is known. When the provider is not known, a
    // creation is treated as generated from cakeys' templates (`Some(false)`), because how the
    // provider generates is not known either, and the templates rule was deferred above.
    let own = out.own.or_else(|| creating.then_some(false));
    let needs = match needs(t, mode, own) {
        Ok(n) => n,
        Err(e) => return Ok(out.refuse(Rule::Capability, e)),
    };
    profile_rules(t, mode, provider, &needs, own, profiles, &mut out)?;
    Ok(out)
}

/// The part of [`static_rules`] that the capability profiles decide: the proof, the templates
/// (checked with `provider` when the provider is known), each mechanism group of `needs`, the
/// generation and the commitments.
fn profile_rules(
    t: &Target,
    mode: Mode,
    provider: Option<&dyn Provider>,
    needs: &Needs,
    own: Option<bool>,
    profiles: &Profiles,
    out: &mut Verdicts,
) -> Result<()> {
    let token = t.token_name;
    let unsupported = |m: String| KmError::Unsupported(m.into());
    // The proof of possession that will bind the spec's key. A recorded *no* (from a profile or
    // from this token's recorded answers) refuses the pair, because a key made there could not be
    // identified. An *unknown* answer means that the run tries the proof.
    if let Some(cap) = proof(t)
        && let Some(m) = profiles.module.as_ref()
        && m.answer(&cap) == Some(false)
    {
        let why = m.evidence(&cap, "").map_or_else(String::new, |e| format!(": {e}"));
        let refusal = format!("{t}: token '{token}' cannot prove possession by {cap} ({}{why})", m.profile);
        out.refusals.push(Refusal::new(Rule::Capability, unsupported(refusal)));
    }
    let set = Set::active().map_err(|e| KmError::Validation(e.into()))?;
    let baseline = set.baseline().map_err(|e| KmError::Validation(e.into()))?;
    let layers: Vec<&cakeys_profile::Profile> = profiles.layers.iter().collect();
    let eff = Effective::new(baseline, profiles.module.as_ref(), &layers);
    // The templates that the verb will send, after the provider adjusts them. When the provider
    // refuses a template, the run refuses the pair before anything is created (`plan_templates`).
    // For a mechanism whose verdict is unknown, `has` returns `None`.
    if let Some(p) = provider {
        let has = |m: MechanismType| match eff.mechanism(&m.to_string()) {
            Verdict::Yes { .. } => Some(true),
            Verdict::No { .. } => Some(false),
            Verdict::Unknown { .. } => None,
        };
        let derive_sealed = profiles.module.as_ref().and_then(|m| m.answer(&Capability::DeriveSealed));
        let seals = ecdh_seals(derive_sealed, has(MechanismType::SHA256_HMAC));
        match plan_templates(t, mode, own == Some(false), p, &has, seals) {
            Ok(None) => {}
            Ok(Some(why)) => out.defer(Rule::Templates, why),
            Err(e) => out
                .refusals
                .push(Refusal::new(Rule::Templates, e.prefixed(format_args!("{t}: provider '{}'", p.name())))),
        }
    }
    let generation = needs.generation.map(|m| vec![m]);
    for group in needs.groups.iter().chain(&generation) {
        let verdicts: Vec<(String, Verdict)> =
            group.iter().map(|m| (m.to_string(), eff.mechanism(&m.to_string()))).collect();
        if verdicts.iter().any(|(_, v)| matches!(v, Verdict::Yes { .. })) {
            continue;
        }
        let lines: Vec<String> = verdicts.iter().map(|(m, v)| format!("{m}: {v}")).collect();
        if verdicts.iter().all(|(_, v)| matches!(v, Verdict::No { .. })) {
            let refusal = format!("{t}: token '{token}' cannot do what mode '{mode}' needs ({})", lines.join("; "));
            out.refusals.push(Refusal::new(Rule::Capability, unsupported(refusal)));
        } else {
            out.defer(Rule::Capability, format!("{t}: the profiles do not decide ({})", lines.join("; ")));
        }
    }
    // Check the generation's key type, curve and size, and then a secret key's commitments. The
    // commitments are refused only when the profile measured every commitment that the spec
    // declares and the module can compute none of them. The module's advertised mechanism list
    // decides a commitment that the profile did not measure. The commitments are deferred when
    // none of them is a yes and some are undecided, as for a generation.
    let generated = needs.generation.and_then(|_| generating(t, &eff, token));
    for said in generated.into_iter().chain(commitments(t, &eff, token)) {
        match said {
            Ok(refusal) => out.refusals.push(Refusal::new(Rule::Capability, unsupported(refusal))),
            Err(undecided) => out.defer(Rule::Capability, undecided),
        }
    }
    Ok(())
}

/// Returns the capability of proving possession of the private key of `t` in the way that its
/// spec binds the key (`plan::expected_binding`). Returns `None` when that binding is not a proof.
fn proof(t: &Target) -> Option<Capability> {
    proof_capability(&t.object, cakeys_core::plan::expected_binding(t)?)
}

/// Returns what a capability row of `object` is about: the object's curve, or else its modulus
/// size.
fn on(object: &ObjectCfg) -> Option<On> {
    match (&object.curve, object.modulus_bits) {
        (Some(c), _) => Some(On::Item(c.clone())),
        (None, Some(bits)) => Some(On::Bits(u32::try_from(bits).ok()?)),
        (None, None) => None,
    }
}

/// Returns the capability row for a proof of possession of the private key of `object` by
/// `binding` (`prove.<proof>.<key type>.<curve or size>`). Returns `None` for `token-asserted`,
/// which is not a proof, and for a key that has no key type or has neither a curve nor a size.
pub(crate) fn proof_capability(object: &ObjectCfg, binding: cakeys_core::config::Binding) -> Option<Capability> {
    Some(Capability::Prove {
        binding: binding.proof_name()?.into(),
        key_type: object.key_type?.name().into(),
        on: on(object)?,
    })
}

/// Returns the capability row for the generation of `object`
/// (`generate.<key type>.<curve or size>`).
pub(crate) fn generate_capability(object: &ObjectCfg) -> Option<Capability> {
    Some(Capability::Generate { key_type: object.key_type?.name().into(), on: on(object)? })
}

/// Returns what the profiles say about the generation of the key of `t` with its type, curve and
/// size. `Some(Ok)` holds the refusal. `Some(Err)` holds the reason for a deferral when the
/// profiles do not decide. `None` means that the answer is yes or that `t` names no key type.
fn generating(t: &Target, eff: &Effective, token: &str) -> Option<std::result::Result<String, String>> {
    let kt = t.object.key_type?;
    let verdict = if kt.is_asymmetric() {
        let bits = t.object.modulus_bits.and_then(|b| u32::try_from(b).ok());
        eff.generate(kt.name(), t.object.curve.as_deref(), bits)
    } else {
        // A secret key's length is `valueLen` from keys.toml, or else the length that its key
        // type fixes.
        let bytes = t.object.value_len.or_else(|| kt.fixed_value_len());
        eff.generate_secret(kt.name(), bytes.and_then(|b| u32::try_from(b).ok()))
    };
    match verdict {
        Verdict::Yes { .. } => None,
        v @ Verdict::No { .. } => Some(Ok(format!("{t}: token '{token}' cannot generate it: {v}"))),
        v @ Verdict::Unknown { .. } => Some(Err(format!("{t}: generation not decided: {v}"))),
    }
}

/// Returns what the profiles say about the declared commitments of `t` when `t` is a secret key.
/// `Some(Ok)` holds the refusal, when the profile measured every commitment as one that the
/// module cannot compute. `Some(Err)` holds the reason for a deferral, when no commitment is a yes
/// and a commitment that the profile measured is not decided at this key length (review
/// 2026-11-23 A-1). `None` means that a commitment is a yes, that there are no commitments, or
/// that the undecided commitments were never measured, so that the advertised mechanism list
/// decides them.
fn commitments(t: &Target, eff: &Effective, token: &str) -> Option<std::result::Result<String, String>> {
    let kt = t.object.key_type.filter(|_| t.object.class == Class::SecretKey)?;
    let bytes = t.object.value_len.or_else(|| kt.fixed_value_len()).and_then(|b| u32::try_from(b).ok());
    let verdicts: Vec<(&str, Verdict)> = declared_commits(t)
        .iter()
        .map(|c| {
            let kind = c.profile_kind();
            (kind, eff.commit(kind, kt.name(), bytes))
        })
        .collect();
    if verdicts.is_empty() || verdicts.iter().any(|(_, v)| matches!(v, Verdict::Yes { .. })) {
        return None;
    }
    let lines: Vec<String> = verdicts.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    if verdicts.iter().all(|(_, v)| matches!(v, Verdict::No { .. })) {
        return Some(Ok(format!("{t}: token '{token}' computes none of its commitments ({})", lines.join("; "))));
    }
    verdicts
        .iter()
        .any(|(k, v)| matches!(v, Verdict::Unknown { .. }) && eff.measured_commit(k, kt.name()))
        .then(|| Err(format!("{t}: commitments not decided ({})", lines.join("; "))))
}
