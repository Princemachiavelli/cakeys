//! The rules a pair is held to before anything is written, each with a name ([`Rule`]): a rule
//! that refuses says which it is ([`Refusal`]), and one that only the write can decide says so
//! ([`Deferred`]), never nothing. [`static_rules`] are the ones decided without a token, asked by
//! every entry path through this one function: the static gate (`validate`, `create`'s plan,
//! [`crate::gate::check`]) and the live checks before a write ([`check_capabilities`],
//! [`check_import`], and `Token::create` for placement), so no path can skip one (review
//! 2026-11-24 B-1, B-2; docs/archive/REVIEW-2026-11-24/phase1-design.md §1.3).

#[allow(
    clippy::wildcard_imports,
    reason = "the ops/ split files work on the parent module's imports, as token/'s (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;
use crate::resolution::Resolved as Profiles;
use cakeys_core::config::ObjectCfg;
use cakeys_profile::{Capability, Effective, On, Set, Verdict};

/// The rules, each with the one name refusals, deferrals and the JSON rows carry.
macro_rules! rules {
    ($($(#[$doc:meta])* $variant:ident = $name:literal,)*) => {
        /// A rule a plan asks before a write (docs/CAKEYS.md, "Rules").
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Rule {
            $($(#[$doc])* $variant,)*
        }

        impl Rule {
            /// Every rule, in declaration order.
            pub const ALL: &[Rule] = &[$(Rule::$variant),*];

            /// Its name, as refusals and the JSON rows say it.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $(Rule::$variant => $name,)*
                }
            }
        }
    };
}

rules! {
    /// Where the module may place a key ([`Provider::placement`]): 17.
    Placement = "placement",
    /// An attestation the spec opts into, which the provider computes for the class: 15.
    AttestationCover = "attestation-cover",
    /// An attestation of a key that is imported, which the provider gives only for one the
    /// device generated (PIV): 15.
    ImportedAttestation = "imported-attestation",
    /// A key the module generates from its own template only, which it refuses to make as
    /// declared ([`Provider::generation`]): 15 or 17.
    OwnGeneration = "own-generation",
    /// The templates the write sends, as the provider adjusts them ([`Provider::template`]): the
    /// provider's refusal, 15 or 17.
    Templates = "templates",
    /// What the token can do: the mechanisms, the generation, the proof and the commitments, by
    /// its capability profiles or the open token: 15.
    Capability = "capability",
    /// Nothing else under the locator a creation is made under: 13.
    LocatorFree = "locator-free",
    /// A key the lock does not pin already under the locator `create` makes it under: 19.
    UnpinnedExists = "unpinned-exists",
    /// The lock pins material the token does not hold: a new generation could never match: 14.
    PinnedLost = "pinned-lost",
    /// An object only a login shows, asked of a session without one: 16.
    NeedsLogin = "needs-login",
    /// The object holds the identity a delete expects: 14.
    IfMatch = "if-match",
    /// The module's profile says its `C_DestroyObject` does not remove objects of the class: 15.
    DeleteRefused = "delete-refused",
    /// What a delete destroyed is still under the locator: 16.
    DeleteKept = "delete-kept",
    /// The lock can be written: 21.
    LockWritable = "lock-writable",
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A rule's refusal of a pair: the error the run ends with, carrying the rule's name
/// ([`KmError::rule`]); the exit code is the error's.
#[derive(Debug)]
pub struct Refusal {
    /// The rule that refused.
    pub rule: Rule,
    /// Why, as the run reports it.
    pub error: KmError,
}

impl Refusal {
    /// `rule`'s refusal with `error`, which then names it.
    #[must_use]
    pub fn new(rule: Rule, error: KmError) -> Refusal {
        Refusal { rule, error: error.with_rule(rule.name()) }
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

/// A rule a plan could not decide, and why: only the write can (the provider is known only when
/// the token opens, the profiles do not say). Never a pass: the run asks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    /// The rule.
    pub rule: Rule,
    /// Why it is not decided here, led by the pair it is about.
    pub why: String,
}

impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (deferred: {})", self.why, self.rule)
    }
}

/// `deferred` as lines, one per pair and reason: `<why> (deferred: <rule>, <rule>)`, the rules
/// in the order they were deferred.
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

/// The provider a plan asks: the one that will run the write, or why it is not known yet. An
/// unresolved seat defers every provider rule that applies, never skips it.
pub enum Seat<'a> {
    /// The provider the write runs with.
    Resolved(&'a dyn Provider),
    /// Not known until the token opens (no `provider` and nothing recorded in the lock, or one
    /// this build lacks): why.
    Unresolved(String),
}

/// The write a plan is for, which decides the rules that apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `create` generates the object.
    Create,
    /// An import puts its material there (camigrate).
    Import,
    /// It is there: `lock` records it, `create` verifies it.
    Lock,
}

impl Verb {
    /// What `t`'s pair asks of a run with `lock`: `create` generates it where its origin is
    /// `create` and the lock does not pin it ([`creates`]), camigrate imports it where its origin
    /// is `import` or `file`, and anything else is found there.
    #[must_use]
    pub fn of(t: &Target, lock: &Lock) -> Verb {
        match t.on_token.key_origin() {
            _ if creates(t, lock) => Verb::Create,
            KeyOrigin::Import | KeyOrigin::File => Verb::Import,
            KeyOrigin::Create | KeyOrigin::Adopt => Verb::Lock,
        }
    }
}

/// What [`static_rules`] found for a pair.
#[derive(Debug, Default)]
pub struct Verdicts {
    /// Why the pair cannot be realised, each with its rule.
    pub refusals: Vec<Refusal>,
    /// What only the write can decide.
    pub deferred: Vec<Deferred>,
    /// Whether a created key is generated from the module's own template, where that was asked
    /// ([`own_generation`]).
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

    /// The first refusal, as the error a run ends with.
    ///
    /// # Errors
    ///
    /// That refusal.
    pub fn first(self) -> Result<Verdicts> {
        let Verdicts { mut refusals, deferred, own } = self;
        if refusals.is_empty() {
            return Ok(Verdicts { refusals, deferred, own });
        }
        Err(refusals.swap_remove(0).into())
    }
}

/// Refuse (16) where `t`'s object was not found and a session without login could not have seen
/// it ([`Target::needs_login`]): such a session never reports it absent, nor a locator free
/// (review 2026-11-24 B-4). `cannot` says what it cannot tell.
///
/// # Errors
///
/// `Unavailable` (16), naming the rule, on a session without login.
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

/// Whether a key may be made under `loc` on `provider`'s module ([`Provider::placement`]): the
/// one place it is asked, for a pair's key ([`static_rules`]) and for every creation
/// (`Token::create`).
///
/// # Errors
///
/// The provider's refusal (17), naming the rule.
pub(crate) fn placement(provider: &dyn Provider, class: Class, loc: &cakeys_core::config::Locator) -> Result<()> {
    if !class.is_key() {
        return Ok(());
    }
    provider.placement(loc).map_err(|e| Refusal::new(Rule::Placement, e).into())
}

/// The rules of `t` in `mode` decided without a token, for the write `verb`, by the provider in
/// `seat` and, with `profiles` (the token's profile stack, as the static gate resolves it), by
/// the capability profiles:
///
/// - placement, for a key the write puts on the token (`create` generates it, or it is
///   imported); `lock` writes none;
/// - attestation cover, where the spec opts into an attestation;
/// - imported attestation, where the key is imported;
/// - own generation, where `create` generates the key;
/// - with `profiles`: the templates the write sends, the mechanisms, the proof, the generation
///   and a secret key's commitments, a profile's *no* refusing and its *unknown* deferred to the
///   open token.
///
/// A refusal that makes the rest meaningless (placement, own generation, a key type cakeys does
/// not manage) is the only one. With an unresolved seat each provider rule that applies is
/// deferred, and without `profiles` what the token can do as well. Without `profiles` and with
/// the provider, the open token decides what they would right after (the live check).
///
/// # Errors
///
/// `Validation` (17) when no profile set is active.
pub fn static_rules(t: &Target, mode: Mode, seat: Seat, verb: Verb, profiles: Option<&Profiles>) -> Result<Verdicts> {
    let mut out = Verdicts::default();
    let (creating, imported) = (verb == Verb::Create, verb == Verb::Import);
    let placed = t.object.class.is_key() && (creating || imported);
    let provider = match seat {
        Seat::Resolved(p) => Some(p),
        Seat::Unresolved(why) => {
            // Without profiles too, what the token can do is known only when it opens.
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
    // Generated from cakeys' templates: the provider generates from its own, or is not known
    // (then neither is how it generates, and the generation's templates are deferred above).
    let own = out.own.or_else(|| creating.then_some(false));
    let needs = match needs(t, mode, own) {
        Ok(n) => n,
        Err(e) => return Ok(out.refuse(Rule::Capability, e)),
    };
    profile_rules(t, mode, provider, &needs, own, profiles, &mut out)?;
    Ok(out)
}

/// The capability profiles' half of [`static_rules`]: the proof, the templates (asked of
/// `provider` when known), each mechanism group of `needs`, the generation and the commitments.
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
    // The proof the spec's key will be bound by: a profile's or this token's recorded no
    // refuses (a key made could not then be identified); unknown means try.
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
    // The templates the verb will send, as the provider adjusts them: what it refuses, the run
    // refuses before anything is created (`plan_templates`). Unknown means not asked.
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
    // The generation's type, curve and size; then a secret key's commitments: refused only when
    // the profile measured every one the spec declares and the module cannot compute any (an
    // unmeasured one is the advertised list's); deferred when none is a yes and some are
    // undecided, as for a generation.
    let generated = needs.generation.and_then(|_| generating(t, &eff, token));
    for said in generated.into_iter().chain(commitments(t, &eff, token)) {
        match said {
            Ok(refusal) => out.refusals.push(Refusal::new(Rule::Capability, unsupported(refusal))),
            Err(undecided) => out.defer(Rule::Capability, undecided),
        }
    }
    Ok(())
}

/// The capability of proving `t`'s private key the way its spec binds it
/// (`plan::expected_binding`), when that is a proof.
fn proof(t: &Target) -> Option<Capability> {
    proof_capability(&t.object, cakeys_core::plan::expected_binding(t)?)
}

/// What a capability row of `object` is on: its curve, or its modulus size.
fn on(object: &ObjectCfg) -> Option<On> {
    match (&object.curve, object.modulus_bits) {
        (Some(c), _) => Some(On::Item(c.clone())),
        (None, Some(bits)) => Some(On::Bits(u32::try_from(bits).ok()?)),
        (None, None) => None,
    }
}

/// The capability a proof of possession of `object`'s private key by `binding` is
/// (`prove.<proof>.<key type>.<curve or size>`); `None` for `token-asserted`, or a key with
/// neither a curve nor a size.
pub(crate) fn proof_capability(object: &ObjectCfg, binding: cakeys_core::config::Binding) -> Option<Capability> {
    Some(Capability::Prove {
        binding: binding.proof_name()?.into(),
        key_type: object.key_type?.name().into(),
        on: on(object)?,
    })
}

/// The capability generating `object` is (`generate.<key type>.<curve or size>`).
pub(crate) fn generate_capability(object: &ObjectCfg) -> Option<Capability> {
    Some(Capability::Generate { key_type: object.key_type?.name().into(), on: on(object)? })
}

/// What the profiles say of generating `t`'s key, its type, curve and size: `Ok`, the refusal;
/// `Err`, why it is deferred, when undecided; `None` when it is a yes or `t` names no key type.
fn generating(t: &Target, eff: &Effective, token: &str) -> Option<std::result::Result<String, String>> {
    let kt = t.object.key_type?;
    let verdict = if kt.is_asymmetric() {
        let bits = t.object.modulus_bits.and_then(|b| u32::try_from(b).ok());
        eff.generate(kt.name(), t.object.curve.as_deref(), bits)
    } else {
        // A secret key's length: keys.toml's `valueLen`, or what its type fixes.
        let bytes = t.object.value_len.or_else(|| kt.fixed_value_len());
        eff.generate_secret(kt.name(), bytes.and_then(|b| u32::try_from(b).ok()))
    };
    match verdict {
        Verdict::Yes { .. } => None,
        v @ Verdict::No { .. } => Some(Ok(format!("{t}: token '{token}' cannot generate it: {v}"))),
        v @ Verdict::Unknown { .. } => Some(Err(format!("{t}: generation not decided: {v}"))),
    }
}

/// What the profiles say of `t`'s declared commitments when it is a secret key: `Ok`, the
/// refusal, when the profile measured every one as one the module cannot compute; `Err`, why it
/// is deferred, when none is a yes and one the profile measured is not decided at this length
/// (review 2026-11-23 A-1); `None` when one is a yes, there are none, or the undecided ones were
/// never measured (the advertised list's).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule has a name of its own, and the names are the ones the JSON rows and the docs
    /// use: kebab-case, never reused.
    #[test]
    fn every_rule_has_its_own_name() {
        let names: std::collections::BTreeSet<&str> = Rule::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(names.len(), Rule::ALL.len());
        for n in names {
            assert!(n.chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{n}");
        }
    }
}
