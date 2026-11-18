//! The `supports` query (docs/CAPROBE.md): what the capability profiles say a module
//! supports. Pure data — no token is touched.

use cakeys_core::config::Config;
use cakeys_core::{KmError, Result};
use cakeys_profile::{Effective, Profile, Set, Verdict};

/// The question a [`Query`] asks.
pub(crate) enum Ask<'a> {
    /// A mechanism (`CKM_*`), key type (`CKK_*`), parameter set (`CKP_*`) or curve.
    Name(&'a str),
    /// The members of a baseline class.
    Class(&'a str),
    /// The RSA-OAEP hashes usable for wrapping.
    Oaep,
}

/// What to ask the profiles.
pub(crate) struct Query<'a> {
    pub ask: Ask<'a>,
    /// The module profile, by name or family.
    pub profile: Option<&'a str>,
    /// Else the token in keys.toml whose `provider` names the profile family.
    pub token: Option<&'a str>,
    /// Delta layers on top of the binding layer, which is always in the stack.
    pub layers: &'a [String],
    /// An RSA modulus size to ask about (with a `CKK_RSA` name).
    pub bits: Option<u32>,
}

/// What a [`Query`] resolved and answered.
pub(crate) struct Support {
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
    pub(crate) fn outcome(&self) -> Result<()> {
        let no: Vec<&str> =
            self.verdicts.iter().filter(|(_, v)| matches!(v, Verdict::No { .. })).map(|(n, _)| n.as_str()).collect();
        if !no.is_empty() {
            return Err(KmError::Unsupported(format!("not supported: {}", no.join(", ")).into()));
        }
        if self.verdicts.iter().any(|(_, v)| matches!(v, Verdict::Unknown { .. })) {
            return Err(KmError::Unavailable(
                "the profiles do not decide this: run the probe (docs/CAPROBE.md) or a fuller profile".into(),
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
/// `Validation` (17) for an unknown profile, layer, class or token, or a token that names no
/// provider.
pub(crate) fn supports(cfg: &Config, set: &Set, q: &Query) -> Result<Support> {
    let find = |name: &str| set.find(name).map_err(|e| KmError::Validation(e.into()));
    // A family with pairs on several kinds of hardware (tpm2-pkcs11/1.10+swtpm, +amd-ftpm):
    // the hardware layer asked for names the pair, as in token resolution.
    let find_module = |name: &str, hardware: &[String]| {
        set.find(name)
            .or_else(|e| {
                let named: Vec<&Profile> = set
                    .all()
                    .iter()
                    .filter(|p| p.family() == name && hardware.iter().any(|h| p.profile.ends_with(&format!("+{h}"))))
                    .collect();
                if let [p] = named.as_slice() { Ok(*p) } else { Err(e) }
            })
            .map_err(|e| KmError::Validation(e.into()))
    };
    let module = match (q.profile, q.token) {
        (Some(p), _) => Some(find_module(p, q.layers)?),
        (None, Some(t)) => {
            let token = cfg.tokens.get(t).ok_or_else(|| KmError::Validation(format!("unknown token '{t}'").into()))?;
            // The one profile `moduleProfile` names, else the provider's family.
            let named = token.module_profile.as_deref().or(token.provider.as_deref()).ok_or_else(|| {
                KmError::Validation(
                    format!("token '{t}' names no provider; set tokens.{t}.provider or pass --profile").into(),
                )
            })?;
            Some(find_module(named, &token.profiles)?)
        }
        (None, None) => None,
    };
    // The cryptoki binding layer is always in the stack (docs/CAPROBE.md): what it
    // subtracts is decided by the build this binary runs against, so an explicit `--layer
    // cryptoki/0.12` adds nothing it has not already decided.
    let mut resolved: Vec<Profile> = vec![cakeys_pkcs11::binding::layer().map_err(|e| KmError::Validation(e.into()))?];
    for l in q.layers {
        let p = find(l)?;
        if p.profile != cakeys_pkcs11::binding::NAME {
            resolved.push(p.clone());
        }
    }
    let stack: Vec<&Profile> = resolved.iter().collect();
    let baseline = set.baseline().map_err(|e| KmError::Validation(e.into()))?;
    let eff = Effective::new(baseline, module, &stack);
    let verdicts = match q.ask {
        Ask::Class(class) => eff.class(class).ok_or_else(|| {
            KmError::Validation(
                format!(
                    "no class '{class}' in baseline {} (classes: {})",
                    baseline.baseline,
                    baseline.class.keys().cloned().collect::<Vec<_>>().join(", ")
                )
                .into(),
            )
        })?,
        Ask::Oaep => eff.oaep(),
        Ask::Name(name) => vec![(name.to_owned(), eff.query(name, q.bits))],
    };
    Ok(Support {
        module: module.map_or_else(|| "(none)".to_owned(), |m| m.profile.clone()),
        layers: resolved.iter().map(|p| p.profile.clone()).collect(),
        verdicts,
    })
}
