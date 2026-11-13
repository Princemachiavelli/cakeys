//! The `supports` query (docs/PROVIDERS.md): what the capability profiles say a module
//! supports. Pure data — no token is touched.

use cakeys_core::config::Config;
use cakeys_core::{KmError, Result};
use cakeys_profile::{Effective, Profile, Set, Verdict};

/// What to ask the profiles.
#[derive(Default)]
pub struct Query<'a> {
    /// A mechanism (`CKM_*`), key type (`CKK_*`), parameter set (`CKP_*`) or curve.
    pub name: Option<&'a str>,
    /// The module profile, by name or family.
    pub profile: Option<&'a str>,
    /// Else the token in keys.toml whose `provider` names the profile family.
    pub token: Option<&'a str>,
    /// Delta layers on top of the binding layer, which is always in the stack.
    pub layers: &'a [String],
    /// List the members of a baseline class instead of asking for `name`.
    pub class: Option<&'a str>,
    /// List the RSA-OAEP hashes usable for wrapping instead of asking for `name`.
    pub oaep: bool,
    /// An RSA modulus size to ask about (with a `CKK_RSA` name).
    pub bits: Option<u32>,
}

/// What a [`Query`] resolved and answered.
pub struct Support {
    /// The resolved module profile's name ("(none)" without one).
    pub module: String,
    /// The stack's layer names, the binding layer first.
    pub layers: Vec<String>,
    /// One verdict per asked name.
    pub verdicts: Vec<(String, Verdict)>,
}

impl Support {
    /// The verdicts as one outcome.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) when any verdict is no; `Unavailable` (16) when the profiles do not
    /// decide one.
    pub fn outcome(&self) -> Result<()> {
        let no: Vec<&str> =
            self.verdicts.iter().filter(|(_, v)| matches!(v, Verdict::No { .. })).map(|(n, _)| n.as_str()).collect();
        if !no.is_empty() {
            return Err(KmError::Unsupported(format!("not supported: {}", no.join(", "))));
        }
        if self.verdicts.iter().any(|(_, v)| matches!(v, Verdict::Unknown { .. })) {
            return Err(KmError::Unavailable(
                "the profiles do not decide this: run the probe (PROVIDERS.md phase 3) or a fuller profile".into(),
            ));
        }
        Ok(())
    }
}

/// Answer `q` from `set`: the module profile (named, or through a token's `provider` in
/// `cfg`), the delta layers on top, and the verdicts.
///
/// # Errors
///
/// `Validation` (17) for an unknown profile, layer, class or token, a token that names no
/// provider, or a query that asks nothing.
pub fn supports(cfg: &Config, set: &Set, q: &Query) -> Result<Support> {
    let find = |name: &str| set.find(name).map_err(KmError::Validation);
    let module = match (q.profile, q.token) {
        (Some(p), _) => Some(find(p)?),
        (None, Some(t)) => {
            let token = cfg.tokens.get(t).ok_or_else(|| KmError::Validation(format!("unknown token '{t}'")))?;
            let family = token.provider.as_deref().ok_or_else(|| {
                KmError::Validation(format!("token '{t}' names no provider; set tokens.{t}.provider or pass --profile"))
            })?;
            Some(find(family)?)
        }
        (None, None) => None,
    };
    // The cryptoki binding layer is always in the stack (docs/PROVIDERS.md phase 2): what it
    // subtracts is decided by the build this binary runs against, so an explicit `--layer
    // cryptoki/0.12` adds nothing it has not already decided.
    let mut resolved: Vec<Profile> = vec![crate::binding::layer().map_err(KmError::Validation)?];
    for l in q.layers {
        let p = find(l)?;
        if p.profile != "cryptoki/0.12" {
            resolved.push(p.clone());
        }
    }
    let stack: Vec<&Profile> = resolved.iter().collect();
    let baseline = set.baseline().map_err(KmError::Validation)?;
    let eff = Effective::new(baseline, module, &stack);
    let verdicts = match (q.class, q.name) {
        (Some(class), _) => eff.class(class).ok_or_else(|| {
            KmError::Validation(format!(
                "no class '{class}' in baseline {} (classes: {})",
                baseline.baseline,
                baseline.class.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })?,
        (None, _) if q.oaep => eff.oaep(),
        (None, Some(name)) => vec![(name.to_owned(), eff.query(name, q.bits))],
        (None, None) => {
            return Err(KmError::Validation("supports: name what to ask, a class, or the OAEP hashes".into()));
        }
    };
    Ok(Support {
        module: module.map_or_else(|| "(none)".to_owned(), |m| m.profile.clone()),
        layers: resolved.iter().map(|p| p.profile.clone()).collect(),
        verdicts,
    })
}
