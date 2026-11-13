//! The static gate (docs/PROVIDERS.md phase 4): what each spec needs of its token, checked
//! against the token's capability profiles with no token attached — `validate`'s second half.
//! The needs are [`ops::needs`], the same the live check refuses by before anything is created;
//! here a profile's *no* refuses (15, naming the profile that decided it) and its *unknown* is a
//! note, never a failure.
//!
//! A token's profiles resolve statically from what is known without opening it: the module and
//! token its realisations recorded in the lock (D9/D10's match keys), and the `provider` and
//! `profiles` keys.toml names. A token with neither is skipped, with a note.

use crate::ops::{self, Target};
use crate::provider::Registry;
use crate::resolution::{self, Resolved};
use cakeys_core::config::{Lock, Mode, TokenCfg};
use cakeys_core::{KmError, Result};
use cakeys_profile::{Effective, Set, Verdict};

/// A token's profile stack as known without opening it.
pub struct Stack {
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
    let set = Set::embedded().map_err(KmError::Validation)?;
    for p in &cfg.profiles {
        set.find(p).map_err(|e| KmError::Validation(format!("token '{name}': {e}")))?;
    }
    let recorded =
        lock.realisations.values().filter_map(|by_token| by_token.get(name)).find_map(|r| r.provenance.as_ref());
    let Some(provider) = cfg.provider.clone().or_else(|| recorded.map(|p| p.provider.clone())) else {
        return Ok(Err(format!(
            "token '{name}': no provider named and nothing recorded in the lock, so its profile is known \
             only when it opens"
        )));
    };
    let (module, token, source) = match recorded {
        Some(p) => (p.module.clone(), Some(p.token.clone()), "the lock's recorded module and token"),
        None => (crate::migrate::moduleless_info(), None, "keys.toml's provider"),
    };
    // What resolution cannot decide without the token (several profiles of a family, none
    // matching) is not a config error here: the open decides it.
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
            Ok(Stack { resolved, provider, source })
        }
        Err(e) => Err(format!("token '{name}': {e}")),
    })
}

/// What the gate found for one target: refusals (each a line) and notes.
#[derive(Default)]
pub struct Verdicts {
    pub refusals: Vec<String>,
    pub notes: Vec<String>,
}

/// Check `t` in `mode` against `stack`: every mechanism group [`ops::needs`] lists, the
/// generation of the object's type, curve and size when the spec creates it, and an attestation
/// the provider must produce.
///
/// # Errors
///
/// [`Set::embedded`]'s parse error (a commit-time bug).
pub fn check(t: &Target, mode: Mode, stack: &Stack, registry: &Registry) -> Result<Verdicts> {
    let mut out = Verdicts::default();
    let needs = match ops::needs(t, mode) {
        Ok(n) => n,
        Err(e) => {
            out.refusals.push(e.to_string());
            return Ok(out);
        }
    };
    if let Some(p) = registry.named(&stack.provider)
        && let Err(m) = ops::check_attestation(t, p.as_ref())
    {
        out.refusals.push(m);
    }
    let set = Set::embedded().map_err(KmError::Validation)?;
    let baseline = set.baseline().map_err(KmError::Validation)?;
    let layers: Vec<&cakeys_profile::Profile> = stack.resolved.layers.iter().collect();
    let eff = Effective::new(baseline, stack.resolved.module.as_ref(), &layers);
    let token = t.token_name;
    for group in &needs.groups {
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
    if needs.generates
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
