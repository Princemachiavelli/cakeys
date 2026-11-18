//! The static gate (docs/CAPROBE.md): what each spec needs of its token, checked
//! against the token's capability profiles with no token attached — `validate`'s second half,
//! and what `create` checks before it opens any token. The needs are [`ops::needs`], the same
//! the live check refuses by before anything is created; here a profile's *no* refuses (15,
//! naming the profile that decided it) and its *unknown* is a note, never a failure. The
//! generation is asked only of a pair `create` makes (`origin = "create"`, not yet pinned).
//!
//! A token's profiles resolve statically from what is known without opening it: the module and
//! token its realisations recorded in the lock (D9/D10's match keys), and the `provider` and
//! `profiles` keys.toml names. A token with neither is skipped, with a note.

use crate::ops::{self, Target};
use crate::provider::Registry;
use crate::resolution::{self, Resolved};
use cakeys_core::config::{Binding, Lock, Mode, ObjectCfg, TokenCfg, TokenObservation};
use cakeys_core::{KmError, Result};
use cakeys_profile::{Capability, Effective, On, Set, Verdict};

/// A token's profile stack as known without opening it.
pub struct Stack {
    /// The module and token profiles the stack resolved to.
    pub resolved: Resolved,
    /// The provider: named in keys.toml, else recorded in the lock.
    pub provider: String,
    /// Where the module and token came from, for messages.
    pub source: &'static str,
}

/// Resolve token `name`'s profiles from keys.toml and the lock. `Ok(None)` when nothing says
/// which module the token is (no `provider`, no recorded realisation), with the reason.
///
/// # Errors
///
/// `Validation` (17) for a profile keys.toml names in `tokens.<t>.profiles` that no loaded
/// profile set has — a config error, as at token open.
pub fn stack(name: &str, cfg: &TokenCfg, lock: &Lock) -> Result<std::result::Result<Stack, String>> {
    let set = Set::active().map_err(|e| KmError::Validation(e.into()))?;
    for p in &cfg.profiles {
        set.find(p).map_err(|e| KmError::Validation(format!("token '{name}': {e}").into()))?;
    }
    let observed = match lock.token_observation(name) {
        TokenObservation::One(o) => Some(o),
        TokenObservation::None => None,
        TokenObservation::Several(groups) => {
            return Ok(Err(format!(
                "{}, so its profile is known only when it opens",
                TokenObservation::several(name, &groups)
            )));
        }
    };
    let recorded = observed.and_then(|o| Some((o.module.as_ref()?, o.token.as_ref()?)));
    let Some(provider) = cfg.named_provider().map(str::to_owned).or_else(|| observed.and_then(|o| o.provider.clone()))
    else {
        return Ok(Err(format!(
            "token '{name}': no provider named and nothing recorded in the lock, so its profile is known \
             only when it opens"
        )));
    };
    let (module, token, source) = match recorded {
        Some((m, t)) => (m.clone(), Some(t.clone()), "the lock's recorded module and token"),
        None => (crate::resolution::moduleless_info(), None, "keys.toml's provider"),
    };
    // What resolution refuses (a profile set that does not parse) is not a config error here:
    // the open decides it.
    Ok(match resolution::resolve(cfg, &module, token.as_ref(), &provider) {
        Ok(mut resolved) => {
            if let Some(o) = observed {
                resolved.with_answers(name, o);
            }
            if recorded.is_none() {
                // Resolution's version notes compare against a module nobody has seen yet.
                resolved.notes = vec![format!(
                    "module profile {} chosen by provider alone: no module recorded yet, so neither \
                     its version nor its hardware is checked",
                    resolved.module_name().unwrap_or("(none)")
                )];
            }
            Ok(Stack { resolved, provider, source })
        }
        Err(e) => Err(format!("token '{name}': {e}")),
    })
}

/// The capability of proving `t`'s private key the way its spec binds it
/// (`plan::expected_binding`), when that is a proof.
fn proof(t: &Target) -> Option<Capability> {
    proof_capability(t.object, cakeys_core::plan::expected_binding(t)?)
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
pub(crate) fn proof_capability(object: &ObjectCfg, binding: Binding) -> Option<Capability> {
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

/// What the gate found for one target: refusals (each a line) and notes.
#[derive(Default)]
pub struct Verdicts {
    /// Why the target cannot be realised on this token, one line each (15).
    pub refusals: Vec<String>,
    /// What the gate could not decide (a profile's *unknown*), one line each.
    pub notes: Vec<String>,
}

/// Check `t` in `mode` against `stack`: every mechanism group [`ops::needs`] lists, an
/// attestation the provider must produce, and when `creates` (`create` makes the object,
/// [`ops::creates`]) its generation: the mechanism, and the type, curve and size.
///
/// # Errors
///
/// `Validation` (17) when no profile set is active ([`Registry::named`]).
pub fn check(t: &Target, mode: Mode, stack: &Stack, registry: &Registry, creates: bool) -> Result<Verdicts> {
    let mut out = Verdicts::default();
    let provider = registry.named(&stack.provider)?;
    // A module that generates from its own template refuses what it cannot make (kmsp11).
    let own = match provider.as_ref().filter(|_| creates).map(|p| ops::own_generation(t, p.as_ref())) {
        Some(Err(e)) => {
            out.refusals.push(e.to_string());
            return Ok(out);
        }
        Some(Ok(own)) => Some(own),
        None => creates.then_some(false),
    };
    let needs = match ops::needs(t, mode, own) {
        Ok(n) => n,
        Err(e) => {
            out.refusals.push(e.to_string());
            return Ok(out);
        }
    };
    if let Some(p) = &provider
        && let Err(m) = ops::check_attestation(t, p.as_ref())
    {
        out.refusals.push(m);
    }
    // The proof the spec's key will be bound by: a profile's or this token's recorded no
    // refuses (a key made could not then be identified); unknown means try.
    if let Some(cap) = proof(t)
        && let Some(m) = stack.resolved.module.as_ref()
        && m.answer(&cap) == Some(false)
    {
        let why = m.evidence(&cap, "").map_or_else(String::new, |e| format!(": {e}"));
        out.refusals
            .push(format!("{t}: token '{}' cannot prove possession by {cap} ({}{why})", t.token_name, m.profile));
    }
    let set = Set::active().map_err(|e| KmError::Validation(e.into()))?;
    let baseline = set.baseline().map_err(|e| KmError::Validation(e.into()))?;
    let layers: Vec<&cakeys_profile::Profile> = stack.resolved.layers.iter().collect();
    let eff = Effective::new(baseline, stack.resolved.module.as_ref(), &layers);
    let token = t.token_name;
    // The templates the verb will send, as the provider adjusts them: what it refuses, the run
    // refuses before anything is created (`ops::plan_templates`). Unknown means not asked.
    if let Some(p) = &provider {
        let has = |m: cryptoki::mechanism::MechanismType| match eff.mechanism(&m.to_string()) {
            Verdict::Yes { .. } => Some(true),
            Verdict::No { .. } => Some(false),
            Verdict::Unknown { .. } => None,
        };
        let derive_sealed = stack.resolved.module.as_ref().and_then(|m| m.answer(&Capability::DeriveSealed));
        let seals = ops::ecdh_seals(derive_sealed, has(cryptoki::mechanism::MechanismType::SHA256_HMAC));
        match ops::plan_templates(t, mode, own == Some(false), p.as_ref(), &has, seals) {
            Ok(None) => {}
            Ok(Some(why)) => out.notes.push(why),
            Err(e) => out.refusals.push(format!("{t}: provider '{}': {e}", p.name())),
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
            out.refusals
                .push(format!("{t}: token '{token}' cannot do what mode '{mode}' needs ({})", lines.join("; ")));
        } else {
            out.notes.push(format!("{t}: the profiles do not decide ({})", lines.join("; ")));
        }
    }
    if needs.generation.is_some()
        && let Some(kt) = t.object.key_type
    {
        let bits = t.object.modulus_bits.and_then(|b| u32::try_from(b).ok());
        match eff.generate(kt.name(), t.object.curve.as_deref(), bits) {
            Verdict::Yes { .. } => {}
            v @ Verdict::No { .. } => {
                out.refusals.push(format!("{t}: token '{token}' cannot generate it: {v}"));
            }
            v @ Verdict::Unknown { .. } => out.notes.push(format!("{t}: generation not decided: {v}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Attributes, Provider, Template};
    use cakeys_core::config::{Binding, Config, ModuleInfo};
    use cakeys_profile::{KeyKind, Proof};
    use std::sync::{Arc, Mutex};

    /// The profile crate names key types and proofs on its own (ISSUES.md Q28): every key type
    /// keys.toml takes and every proof a binding gives is one of its known names, never a name
    /// it keeps as read, so a row the gate asks about is the row a probe wrote.
    #[test]
    fn the_profiles_know_every_key_type_and_proof_cakeys_has() {
        for kt in cakeys_core::types::KeyType::ALL {
            assert!(!matches!(KeyKind::from(kt.name()), KeyKind::Other(_)), "{kt}");
        }
        let proofs = [Binding::PopSign, Binding::PopSignPin, Binding::PopEcdh, Binding::PopDecrypt, Binding::PopUnwrap];
        for b in proofs {
            assert!(!matches!(Proof::from(b.name()), Proof::Other(_)), "{}", b.name());
        }
    }

    /// A provider that records the generation templates it is asked about, refusing them when
    /// it says so.
    struct Asked(Arc<Mutex<Vec<String>>>, bool);

    impl Provider for Asked {
        fn name(&self) -> &'static str {
            "asked"
        }
        fn matches(&self, _: &ModuleInfo) -> bool {
            false
        }
        fn template(&self, req: &Template<'_>, _: &mut Attributes) -> Result<()> {
            if let Template::Generate(_, half) = req {
                self.0.lock().unwrap().push(format!("{half:?}"));
                if self.1 {
                    return Err(KmError::Unsupported("asked refuses".into()));
                }
            }
            Ok(())
        }
    }

    /// The gate asks the provider about the generation `create` will send, with no token: what it
    /// refuses is a refusal here; a verb that creates nothing asks nothing.
    #[test]
    fn the_gate_asks_the_provider_about_a_generation() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_ALLOWED_MECHANISMS = [\"CKM_ECDSA\"] }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"create\" }\n",
        )
        .unwrap();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let stack = Stack { resolved: Resolved::default(), provider: "asked".into(), source: "test" };
        let run = |refuses: bool, creates: bool| {
            let asked = Arc::new(Mutex::new(Vec::new()));
            let registry = Registry::new().with(Asked(Arc::clone(&asked), refuses));
            let v = check(&t, ops::plan_mode(&t).unwrap(), &stack, &registry, creates).unwrap();
            (v.refusals, asked.lock().unwrap().clone())
        };
        assert_eq!(run(false, true), (vec![], vec!["Key".to_owned(), "Public".to_owned()]));
        let (refusals, _) = run(true, true);
        assert!(refusals.iter().any(|r| r.contains("provider 'asked'") && r.contains("asked refuses")), "{refusals:?}");
        assert_eq!(run(true, false), (vec![], vec![]));
    }
}
