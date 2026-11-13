//! Profile resolution (docs/PROVIDERS.md D9, phase 2): which module profile and which delta
//! layers compose a token's effective capability. The binding layer is always there; a
//! forwarder is recognised from the module itself; the config names the rest; the module
//! profile follows the provider family, its version matched against what `C_GetInfo` says —
//! never a module digest — with the one committed version of a family matching by
//! manufacturer alone, flagged low-evidence (kryoptic reports 0.0 [run]).

use crate::binding;
use cakeys_core::config::{ModuleInfo, TokenCfg};
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
/// configured one, which may name the profile exactly, e.g. `provider = "softhsm/2.7"`).
///
/// # Errors
///
/// [`Set::embedded`]'s parse error, or the message of a config-named layer or ambiguous
/// module family: the token open maps both to 17.
pub fn resolve(cfg: &TokenCfg, module: &ModuleInfo, provider: &str) -> Result<Resolved, String> {
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
    //    the selected provider's family. Version by C_GetInfo's expression (D9); the one
    //    committed version of a family matches by manufacturer alone, flagged low-evidence.
    let family = cfg.provider.as_deref().unwrap_or(provider);
    let candidates: Vec<_> = set
        .all()
        .iter()
        .filter(|p| p.mode == Mode::Observed && (p.profile == family || p.family() == family))
        .cloned()
        .collect();
    match candidates.as_slice() {
        [] => {}
        [p] => {
            let p = p.clone();
            if let Some(v) = &p.r#match.module_version
                && module.version != *v
                && cfg.provider.as_deref().is_none_or(|x| x != p.profile)
            {
                out.notes.push(format!(
                    "module profile {} matched by manufacturer alone: the module reports version \
                     '{}' where the profile records '{}'",
                    p.profile, module.version, v
                ));
            }
            out.module = Some(p);
        }
        _ => {
            let p = match candidates
                .iter()
                .find(|p| p.r#match.module_version.as_deref() == Some(module.version.as_str()))
            {
                Some(p) => p.clone(),
                None => {
                    return Err(format!(
                        "several module profiles for '{family}' and none records version '{}': name \
                         one exactly in tokens.<token>.provider ({})",
                        module.version,
                        candidates.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", ")
                    ));
                }
            };
            out.module = Some(p);
        }
    }
    Ok(out)
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
            options: toml::Table::new(),
        }
    }

    #[test]
    fn every_stack_carries_the_binding_layer() {
        let r = resolve(&cfg(None, &[]), &module("Nobody", "1.0"), "generic").unwrap();
        assert!(r.module.is_none());
        assert_eq!(r.layer_names(), ["cryptoki/0.12"]);
    }

    #[test]
    fn the_module_profile_follows_the_provider_family() {
        let r = resolve(&cfg(None, &[]), &module("SoftHSM", "2.7"), "softhsm").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.notes.len(), 0); // the expressed version matches
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), "kryoptic").unwrap();
        assert_eq!(r.module_name(), Some("kryoptic/1.5"));
        assert_eq!(r.notes.len(), 1); // low-evidence: the module hides its version
    }

    #[test]
    fn a_forwarder_is_recognised_and_the_hidden_module_can_be_pinned() {
        // Behind p11-kit the module says so; the provider pin still selects the module profile.
        let r = resolve(&cfg(Some("softhsm"), &[]), &module("PKCS#11 Kit", "0.26"), "p11-kit").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "p11-kit/0.26"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_WRAP"));
    }

    #[test]
    fn the_config_names_extra_layers() {
        let r = resolve(&cfg(None, &["swtpm"]), &module("tpm2-software.github.io", "1.10"), "tpm2-pkcs11").unwrap();
        assert_eq!(r.module_name(), Some("tpm2-pkcs11/1.10"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "swtpm"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_GEN"));
        assert!(resolve(&cfg(None, &["no-such-layer"]), &module("SoftHSM", "2.7"), "softhsm").is_err());
    }
}
