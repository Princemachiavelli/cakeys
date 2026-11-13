//! Profile resolution (docs/PROVIDERS.md D9, phase 2): which module profile and which delta
//! layers compose a token's effective capability. The binding layer is always there; a
//! forwarder is recognised from the module itself; the config names the rest; the module
//! profile follows the provider family, chosen by the most match keys — the version
//! `C_GetInfo` expresses, then the token's model and firmware (D9/D10) —
//! never a module digest; the one committed profile of a family matches by
//! manufacturer alone, flagged low-evidence (kryoptic reports 0.0 [run]).

use crate::binding;
use cakeys_core::config::{ModuleInfo, TokenCfg, TokenInfo};
use cakeys_profile::{Mode, Profile, Set};
use std::collections::BTreeSet;

/// A token's resolved profiles, what [`crate::Token`] carries and every consumer reads.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// The module profile, when one is committed for the selected provider family.
    pub module: Option<Profile>,
    /// The delta layers, innermost first: the binding, any forwarder the module names, the
    /// config's extras.
    pub layers: Vec<Profile>,
    /// What resolution noticed on the way (a low-evidence version match, ...): `caps` prints
    /// them, so a resolved stack is never a silent guess.
    pub notes: Vec<String>,
}

impl Resolved {
    /// The module profile's name, for `caps` and messages.
    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.module.as_ref().map(|p| p.profile.as_str())
    }

    /// The layers' names, in order.
    #[must_use]
    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.iter().map(|p| p.profile.as_str()).collect()
    }

    /// Every mechanism the stack subtracts from a module's advertisement.
    #[must_use]
    pub fn subtracted_mechanisms(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.mechanisms.iter().map(String::as_str))
            .collect()
    }

    /// Every key type the stack subtracts (an unpatched binding's broken ones).
    #[must_use]
    pub fn subtracted_key_types(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.key_types.iter().map(String::as_str))
            .collect()
    }
}

/// Resolve a token's profiles: `provider` is the selected provider's name (or the explicitly
/// configured one, which may name the profile exactly, e.g. `provider = "softhsm/2.7"`);
/// `token` is what `C_GetTokenInfo` gave, when there is a token (its firmware matches a module
/// that hides its version).
///
/// # Errors
///
/// [`Set::embedded`]'s parse error, or the message of a config-named layer or ambiguous
/// module family: the token open maps both to 17.
pub fn resolve(
    cfg: &TokenCfg,
    module: &ModuleInfo,
    token: Option<&TokenInfo>,
    provider: &str,
) -> Result<Resolved, String> {
    let set = Set::embedded()?;
    let mut out = Resolved::default();

    // 1. The binding layer, always: the one between cakeys and every module.
    out.layers.push(binding::layer()?);

    // 2. A forwarder the module itself names (p11-kit's client: C_GetInfo describes it).
    for p in set.all() {
        if p.mode == Mode::Delta
            && p.profile != "cryptoki/0.12"
            && p.r#match.manufacturer.as_deref() == Some(module.manufacturer.as_str())
            && !out.layers.iter().any(|l| l.profile == p.profile)
        {
            out.notes.push(format!(
                "{} is in the path: {} (detected from C_GetInfo)",
                p.profile,
                p.r#match.manufacturer.as_deref().unwrap_or_default()
            ));
            out.layers.push(p.clone());
        }
    }

    // 3. The config's extras, by name or family (the hardware under the module, a forwarder
    //    the module does not name). Explicit means applied, even when nothing detected it.
    for name in &cfg.profiles {
        if out.layers.iter().any(|l| l.profile == name.as_str() || l.family() == name.as_str()) {
            continue;
        }
        let p = set.find(name)?;
        out.layers.push(p.clone());
    }

    // 4. The module profile: the configured provider (family, or exact profile name), else
    //    the selected provider's family. A profile is observed on a module and the hardware
    //    under it (D9/D10), so it is chosen by the most match keys: the expressed version
    //    first (C_GetInfo; a module hiding it as 0.0 records none), then the token's model and
    //    firmware. Anything short of all of them is flagged in the notes.
    let family = cfg.provider.as_deref().unwrap_or(provider);
    let candidates: Vec<&Profile> = set
        .all()
        .iter()
        .filter(|p| p.mode == Mode::Observed && (p.profile == family || p.family() == family))
        .collect();
    if let Some(p) = candidates.iter().find(|p| p.profile == family) {
        // Named exactly in keys.toml: the user's choice, taken as is.
        out.module = Some((*p).clone());
        return Ok(out);
    }
    let fit = |p: &Profile| Fit::of(p, module, token);
    let chosen = match candidates.as_slice() {
        [] => return Ok(out),
        [p] => *p,
        _ => candidates
            .iter()
            .filter(|p| fit(p).version != Some(false))
            .max_by_key(|p| fit(p).hardware_keys())
            .copied()
            .ok_or_else(|| {
                format!(
                    "several module profiles for '{family}' and none records version '{}': name one \
                     exactly in tokens.<token>.provider ({})",
                    module.version,
                    candidates.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", ")
                )
            })?,
    };
    let mut p = chosen.clone();
    let f = fit(&p);
    let seen = |x: Option<&String>| x.map_or_else(|| "unrecorded".to_owned(), |x| format!("'{x}'"));
    match (&p.r#match.module_version, f.firmware) {
        (Some(v), _) if f.version == Some(false) => out.notes.push(format!(
            "module profile {} matched by manufacturer alone: the module reports version '{}' \
             where the profile records '{v}'",
            p.profile, module.version
        )),
        (None, Some(true)) => out.notes.push(format!(
            "module profile {} matched by the token's firmware {}: the module reports version \
             '{}', which says nothing (secondary evidence, D9)",
            p.profile,
            seen(p.r#match.firmware.as_ref()),
            module.version
        )),
        (None, _) => out.notes.push(format!(
            "module profile {} matched by manufacturer alone: the module hides its version and the \
             token's firmware is {} where the profile records {}",
            p.profile,
            seen(token.map(|t| &t.firmware)),
            seen(p.r#match.firmware.as_ref())
        )),
        _ => {}
    }
    if f.model == Some(false) || f.firmware == Some(false) {
        // Another kind of hardware under the same module: what the module advertises still
        // holds, what generates, wraps and unwraps depends on the hardware — unknown, not the
        // observed hardware's answer.
        out.notes.push(format!(
            "module profile {} was observed on model {} firmware {}, this token is model {} \
             firmware {}: its generate, wrap and unwrap rows are not used (unknown)",
            p.profile,
            seen(p.r#match.model.as_ref()),
            seen(p.r#match.firmware.as_ref()),
            seen(token.map(|t| &t.model)),
            seen(token.map(|t| &t.firmware))
        ));
        p.generate.clear();
        p.wrap.oaep = None;
        p.unwrap.refuse = None;
    }
    out.module = Some(p);
    Ok(out)
}

/// How a module profile's match keys meet a token: per key, whether it matches (`None`: the
/// profile records no such key, or there is no token to compare with).
struct Fit {
    version: Option<bool>,
    model: Option<bool>,
    firmware: Option<bool>,
}

impl Fit {
    fn of(p: &Profile, module: &ModuleInfo, token: Option<&TokenInfo>) -> Fit {
        let m = &p.r#match;
        let key = |rec: Option<&String>, live: Option<&String>| rec.zip(live).map(|(r, l)| r == l);
        Fit {
            version: m.module_version.as_ref().map(|v| *v == module.version),
            model: key(m.model.as_ref(), token.map(|t| &t.model)),
            firmware: key(m.firmware.as_ref(), token.map(|t| &t.firmware)),
        }
    }

    /// How many of the hardware keys match: the tie-breaker among one version's profiles.
    fn hardware_keys(&self) -> usize {
        usize::from(self.model == Some(true)) + usize::from(self.firmware == Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(manufacturer: &str, version: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
            description: "d".into(),
            manufacturer: manufacturer.into(),
            version: version.into(),
            cryptoki: "3.2".into(),
        }
    }

    fn cfg(provider: Option<&str>, profiles: &[&str]) -> TokenCfg {
        TokenCfg {
            module: Some("/x.so".into()),
            provider: provider.map(Into::into),
            profiles: profiles.iter().map(|s| (*s).to_owned()).collect(),
            token_label: "t".into(),
            pin_file: None,
            pin_env: None,
            mgm_key_file: None,
            mgm_key_env: None,
            system_feature: None,
            scratch: false,
            options: toml::Table::new(),
        }
    }

    #[test]
    fn every_stack_carries_the_binding_layer() {
        let r = resolve(&cfg(None, &[]), &module("Nobody", "1.0"), None, "generic").unwrap();
        assert!(r.module.is_none());
        assert_eq!(r.layer_names(), ["cryptoki/0.12"]);
    }

    #[test]
    fn the_module_profile_follows_the_provider_family() {
        let r = resolve(&cfg(None, &[]), &module("SoftHSM", "2.7"), None, "softhsm").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.notes.len(), 0); // the expressed version matches
        // kryoptic hides its version (0.0): the token's firmware is the secondary evidence, and
        // either way the match is flagged, never silent.
        let firmware = |f: &str| TokenInfo { model: "v1".into(), serial: "s".into(), firmware: f.into() };
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.5")), "kryoptic").unwrap();
        assert_eq!(r.module_name(), Some("kryoptic/1.5"));
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].contains("by the token's firmware '1.5'"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().wrap.oaep.is_some());
        // Another firmware: flagged, and the hardware-dependent rows answer unknown.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.6")), "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(r.notes[1].contains("are not used"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().generate.is_empty());
        // No token to compare with (a transport file): flagged, rows kept.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), None, "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(!r.module.as_ref().unwrap().generate.is_empty());
    }

    #[test]
    fn another_kind_of_hardware_keeps_the_advertisement_only() {
        // A real TPM under the tpm2-pkcs11 observed on swtpm: what the module lists holds, what
        // it generates, wraps and unwraps depends on the TPM.
        let infineon = TokenInfo { model: "SLB9670".into(), serial: "s".into(), firmware: "7.85".into() };
        let r = resolve(&cfg(None, &[]), &module("tpm2-software.github.io", "1.10"), Some(&infineon), "tpm2-pkcs11")
            .unwrap();
        let m = r.module.as_ref().unwrap();
        assert_eq!(m.profile, "tpm2-pkcs11/1.10+swtpm");
        assert!(!m.advertise.is_empty() && !m.subtract.mechanisms.is_empty());
        assert!(m.generate.is_empty() && m.wrap.oaep.is_none() && m.unwrap.refuse.is_none());
        assert_eq!(r.notes.len(), 1, "{:?}", r.notes);
    }

    #[test]
    fn a_forwarder_is_recognised_and_the_hidden_module_can_be_pinned() {
        // Behind p11-kit the module says so; the provider pin still selects the module profile.
        let r = resolve(&cfg(Some("softhsm"), &[]), &module("PKCS#11 Kit", "0.26"), None, "p11-kit").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "p11-kit/0.26"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_WRAP"));
    }

    #[test]
    fn the_config_names_extra_layers() {
        let r =
            resolve(&cfg(None, &["swtpm"]), &module("tpm2-software.github.io", "1.10"), None, "tpm2-pkcs11").unwrap();
        assert_eq!(r.module_name(), Some("tpm2-pkcs11/1.10+swtpm"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "swtpm"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_GEN"));
        assert!(resolve(&cfg(None, &["no-such-layer"]), &module("SoftHSM", "2.7"), None, "softhsm").is_err());
    }
}
