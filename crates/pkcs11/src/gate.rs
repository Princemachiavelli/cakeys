//! The static gate (docs/CAPROBE.md): what each spec needs of its token, checked
//! against the token's capability profiles with no token attached — `validate`'s second half,
//! and what `create` checks before it opens any token. The needs are [`ops::needs`], the same
//! the live check refuses by before anything is created, and the provider's static rules are the
//! same function's ([`ops::static_rules`]); here a profile's *no* refuses (15, naming the profile
//! that decided it) and its *unknown* is deferred to the open token, never a failure. The
//! generation is asked only of a pair `create` makes (`origin = "create"`, not yet pinned).
//!
//! A token's profiles resolve statically from what is known without opening it: the module and
//! token its realisations recorded in the lock (D9/D10's match keys), and the `provider` and
//! `profiles` keys.toml names. A token with neither is skipped, with a note.

use crate::ops::{self, Target};
use crate::registry::Registry;
use crate::resolution::{self, Resolved};
use cakeys_core::config::{Lock, Mode, TokenCfg, TokenObservation};
use cakeys_core::{KmError, Result};
use cakeys_profile::Set;

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
            if recorded.is_none() {
                // Resolution's version notes compare against a module nobody has seen yet.
                resolved.notes = vec![format!(
                    "module profile {} chosen by provider alone: no module recorded yet, so neither \
                     its version nor its hardware is checked",
                    resolved.module_name().unwrap_or("(none)")
                )];
            }
            // After the notes above, so the one the recorded answers add stays.
            if let Some(o) = observed {
                resolved.with_answers(name, o);
            }
            Ok(Stack { resolved, provider, source })
        }
        Err(e) => Err(format!("token '{name}': {e}")),
    })
}

/// Check `t` in `mode`, for the write `verb` ([`ops::Verb::of`]), against `stack` ([`stack`]'s
/// answer for its token): the static rules ([`ops::static_rules`]) with the provider `stack`
/// names and its profiles: placement, an attestation the provider must produce, every mechanism
/// group [`ops::needs`] lists, and when `create` generates the key its generation, the
/// mechanism and the type, curve and size. A stack that does not resolve, or a provider this
/// build lacks, defers by name what only the open token could decide (review 2026-11-24 B-1).
///
/// # Errors
///
/// `Validation` (17) when no profile set is active ([`Registry::named`]).
pub fn check(
    t: &Target,
    mode: Mode,
    stack: &std::result::Result<Stack, String>,
    registry: &Registry,
    verb: ops::Verb,
) -> Result<ops::Verdicts> {
    let stack = match stack {
        Ok(stack) => stack,
        Err(why) => return ops::static_rules(t, mode, ops::Seat::Unresolved(why.clone()), verb, None),
    };
    let provider = registry.named(&stack.provider)?;
    // A provider this build lacks and no profile names (a downstream one, as in the
    // custom-provider example): what it places, attests and adjusts is known only when the
    // token opens with it.
    let seat = match &provider {
        Some(p) => ops::Seat::Resolved(p.as_ref()),
        None => ops::Seat::Unresolved(format!(
            "provider '{}' is not in this build: what it decides is checked only when the token opens",
            stack.provider
        )),
    };
    ops::static_rules(t, mode, seat, verb, Some(&stack.resolved))
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
    /// The profiles' curve names are their own (`cakeys_profile::baseline::CURVES`, which a
    /// query validates against), and name every curve cakeys has a key type for.
    #[test]
    fn the_profiles_name_every_curve_cakeys_has() {
        for c in cakeys_core::id::Curve::ALL {
            assert!(cakeys_profile::baseline::CURVES.contains(&c.name()), "{}", c.name());
        }
    }

    #[test]
    fn the_profiles_know_every_key_type_and_proof_cakeys_has() {
        for kt in cakeys_core::types::KeyType::ALL {
            assert!(!matches!(KeyKind::from(kt.name()), KeyKind::Other(_)), "{kt}");
        }
        // By the name a capability row is keyed by (`proof_capability`), not the binding's own.
        let proofs = [Binding::PopSign, Binding::PopSignPin, Binding::PopEcdh, Binding::PopDecrypt, Binding::PopUnwrap];
        for b in proofs {
            let name = b.proof_name().unwrap();
            assert!(!matches!(Proof::from(name), Proof::Other(_)), "{name}");
        }
    }

    fn create_config() -> Config {
        toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_ALLOWED_MECHANISMS = [\"CKM_ECDSA\"] }\n\
             tokens.t = { locator = { CKA_LABEL = \"k\" }, origin = \"create\" }\n",
        )
        .unwrap()
    }

    /// A provider this build does not have, and no profile family: the rules only it could
    /// decide are deferred, each named (gate.rs F1), never passed in silence.
    #[test]
    fn a_provider_this_build_lacks_is_said() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let cfg = create_config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let stack =
            |provider: &str| Ok(Stack { resolved: Resolved::default(), provider: provider.into(), source: "test" });
        let v = check(&t, ops::plan_mode(&t).unwrap(), &stack("custom"), &Registry::new(), ops::Verb::Create).unwrap();
        let deferred: Vec<ops::Rule> = v.deferred.iter().map(|d| d.rule).collect();
        for rule in [ops::Rule::Placement, ops::Rule::OwnGeneration, ops::Rule::Templates] {
            assert!(deferred.contains(&rule), "{rule}: {:?}", v.deferred);
        }
        assert!(
            v.deferred
                .iter()
                .all(|d| d.why.contains("provider 'custom' is not in this build") && d.why.contains("token opens")
                    || d.rule == ops::Rule::Capability),
            "{:?}",
            v.deferred
        );
        let v = check(&t, ops::plan_mode(&t).unwrap(), &stack("softhsm"), &Registry::new(), ops::Verb::Create).unwrap();
        assert!(!v.deferred.iter().any(|d| d.why.contains("is not in this build")), "{:?}", v.deferred);

        // A token whose stack does not resolve: every rule a resolved one would ask is deferred,
        // saying why (review 2026-11-24 B-1).
        let unresolved = Err("token 't': no provider named".to_owned());
        let v = check(&t, ops::plan_mode(&t).unwrap(), &unresolved, &Registry::new(), ops::Verb::Create).unwrap();
        let rules: Vec<ops::Rule> = v.deferred.iter().map(|d| d.rule).collect();
        let all = [ops::Rule::Placement, ops::Rule::OwnGeneration, ops::Rule::Templates, ops::Rule::Capability];
        assert_eq!((rules.as_slice(), v.refusals.len()), (all.as_slice(), 0));
        assert!(v.deferred.iter().all(|d| d.why.ends_with("token 't': no provider named")), "{:?}", v.deferred);
    }

    /// A lock observation that recorded answers but no module or token (an older lock): the
    /// stack resolves by provider alone, and both notes stand, the recorded answers' too
    /// (gate.rs F2).
    #[test]
    fn the_recorded_answers_note_survives_the_provider_alone() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\nprovider = \"softhsm\"\n\n\
             [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.s]\nobject = \"k\"\ntokens.t = { locator = { CKA_LABEL = \"k\" } }\n",
        )
        .unwrap();
        let lock: Lock = toml::from_str(
            "version = 1\n\
             [realisations.s.t]\nobject = \"k\"\nlocator = { CKA_LABEL = \"k\" }\nspecDigest = \"sha256-x\"\n\
             mode = \"direct\"\nschemes = []\npolicy = {}\nobservation = \"o\"\n\
             [observations.o.capabilities]\n\"prove.pop-sign.CKK_EC.secp256r1\" = { answer = \"yes\" }\n",
        )
        .unwrap();
        let stack = stack("t", &cfg.tokens["t"], &lock).unwrap().unwrap();
        let notes = &stack.resolved.notes;
        assert!(notes.iter().any(|n| n.contains("answer(s) recorded")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("chosen by provider alone")), "{notes:?}");
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
        let cfg = create_config();
        let t = Target::new(&cfg, "s", "t").unwrap();
        let stack = Ok(Stack { resolved: Resolved::default(), provider: "asked".into(), source: "test" });
        let run = |refuses: bool, creates: bool| {
            let asked = Arc::new(Mutex::new(Vec::new()));
            let registry = Registry::new().with(Asked(Arc::clone(&asked), refuses));
            let verb = if creates { ops::Verb::Create } else { ops::Verb::Lock };
            let v = check(&t, ops::plan_mode(&t).unwrap(), &stack, &registry, verb).unwrap();
            let refusals: Vec<(ops::Rule, String)> = v.refusals.iter().map(|r| (r.rule, r.to_string())).collect();
            (refusals, asked.lock().unwrap().clone())
        };
        assert_eq!(run(false, true), (vec![], vec!["Key".to_owned(), "Public".to_owned()]));
        let (refusals, _) = run(true, true);
        assert!(
            refusals.iter().any(|(rule, r)| *rule == ops::Rule::Templates
                && r.contains("provider 'asked'")
                && r.contains("asked refuses")),
            "{refusals:?}"
        );
        assert_eq!(run(true, false), (vec![], vec![]));
    }
}
