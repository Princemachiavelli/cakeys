//! Which provider a token gets: the one keys.toml names, else the one that detects its module,
//! else the generic one (review 2026-11-23 B-5: the registry is not a provider).

use crate::provider::{Data, Generic, Provider};
use cakeys_core::config::ModuleInfo;
use cakeys_core::{KmError, Result};
use cakeys_profile::Set;
use std::sync::Arc;

/// The module families whose provider is code (the provider crates' names): never stood in
/// for by their profiles' [`Data`] alone, whatever this build links (review 2026-11-24 B-7,
/// B-10, phase1-design §3.2.4).
pub const CODE_FAMILIES: [&str; 4] = ["ykcs11", "tpm2-pkcs11", "kmsp11", "aws-cloudhsm"];

/// Registered providers. The CLI builds one from the provider crates it links; a downstream
/// binary adds its own with [`Registry::with`] (see the `custom-provider` example). A module
/// profile's family is a provider too ([`Data`]), with no code: the registry falls back to the
/// profiles when no code provider is named or claims a module.
#[derive(Clone, Default)]
pub struct Registry {
    providers: Vec<Arc<dyn Provider>>,
}

impl Registry {
    /// An empty registry: no provider beyond [`Generic`] and the profiles' [`Data`] ones.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend the registry with another provider, builder-style: the registry it returns is
    /// the one to use (the `#[must_use]` is load-bearing — the input is consumed).
    #[must_use]
    pub fn with(mut self, p: impl Provider + 'static) -> Self {
        self.providers.push(Arc::new(p));
        self
    }

    /// The names of the code providers registered, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// The provider registered as `name` (or [`Generic`]), else the module profile family of
    /// that name ([`Data`]), without loading any module. A family of [`CODE_FAMILIES`] is its
    /// code's only.
    ///
    /// # Errors
    ///
    /// `Validation` (17) when no profile set is active: never taken for "no such provider"
    /// (ISSUES.md Q24); and when `name` is a family of [`CODE_FAMILIES`] this registry has no
    /// code for.
    pub fn named(&self, name: &str) -> Result<Option<Arc<dyn Provider>>> {
        let set = Set::active().map_err(|e| KmError::Validation(e.into()))?;
        self.named_in(set, name)
    }

    fn named_in(&self, set: &'static Set, name: &str) -> Result<Option<Arc<dyn Provider>>> {
        if name == Generic.name() {
            return Ok(Some(Arc::new(Generic)));
        }
        if let Some(p) = self.providers.iter().find(|p| p.name() == name) {
            return Ok(Some(Arc::clone(p)));
        }
        if CODE_FAMILIES.contains(&name) {
            return Err(unlinked(name));
        }
        let Some(family) = set.module_family_names().into_iter().find(|f| *f == name) else { return Ok(None) };
        Ok(Some(Arc::new(Data(family))))
    }

    /// The explicitly configured provider; else the first registered one that recognises the
    /// module; else the module profile family whose `[match] manufacturer` it reports
    /// ([`Data`]); else [`Generic`].
    ///
    /// # Errors
    ///
    /// `Validation` when `explicit` names neither a provider nor a profile family, or when the
    /// module's manufacturer is claimed by the profiles of several families and none is named.
    pub fn select(&self, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        self.select_in(Set::active().map_err(|e| KmError::Validation(e.into()))?, explicit, module)
    }

    fn select_in(&self, set: &'static Set, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        if let Some(name) = explicit {
            return self.named_in(set, name)?.ok_or_else(|| {
                KmError::Validation(
                    format!(
                        "unknown provider '{name}' (registered: generic, {}; profile families: {})",
                        self.names().join(", "),
                        set.module_family_names().join(", ")
                    )
                    .into(),
                )
            });
        }
        if let Some(p) = self.providers.iter().find(|p| p.matches(module)) {
            return Ok(Arc::clone(p));
        }
        let manufacturer = module.manufacturer.as_str();
        let mut families = set.module_families(manufacturer);
        // A code family is its code's: absent, refused; present and declining the module, the
        // module is not that family's, whatever its manufacturer (B-10).
        if let Some(family) = families.iter().find(|f| CODE_FAMILIES.contains(f) && !self.names().contains(f)) {
            return Err(unlinked(family));
        }
        families.retain(|f| !CODE_FAMILIES.contains(f));
        match families[..] {
            [] => Ok(Arc::new(Generic)),
            [family] => Ok(Arc::new(Data(family))),
            ref families => Err(KmError::Validation(
                format!(
                    "the module's manufacturer '{manufacturer}' is claimed by the profiles of several families \
                 ({}): name one in `provider`",
                    families.join(", ")
                )
                .into(),
            )),
        }
    }
}

/// A family of [`CODE_FAMILIES`] whose code this registry lacks.
fn unlinked(family: &str) -> KmError {
    KmError::Validation(
        format!(
            "provider '{family}' is code this build does not link (a feature of cakeys-cli-common, or a \
             platform it does not build for): its profiles alone would run the token without its rules"
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Acme;
    impl Provider for Acme {
        fn name(&self) -> &'static str {
            "acme"
        }
        fn matches(&self, m: &ModuleInfo) -> bool {
            m.manufacturer == "Acme"
        }
    }

    /// A code provider for a manufacturer the profiles also name (`SoftHSM`'s).
    struct Mine;
    impl Provider for Mine {
        fn name(&self) -> &'static str {
            "mine"
        }
        fn matches(&self, m: &ModuleInfo) -> bool {
            m.manufacturer == "SoftHSM"
        }
    }

    fn module(manufacturer: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
            hash: None,
            description: "d".into(),
            manufacturer: manufacturer.into(),
            version: "1.0".into(),
            cryptoki: "2.40".into(),
        }
    }

    /// A code family's own provider declining (`matches` false): the registry's ykcs11 when the
    /// module is a `YubiHSM`, which Yubico also makes.
    struct Declines(&'static str);
    impl Provider for Declines {
        fn name(&self) -> &'static str {
            self.0
        }
        fn matches(&self, _: &ModuleInfo) -> bool {
            false
        }
    }

    /// A family whose provider is code never resolves to its profiles' data alone (review
    /// 2026-11-24 B-7, B-10): named or detected, a build without that code refuses (17) rather
    /// than run its tokens with none of the code's rules; and once the family's code declined a
    /// module, the module is not that family's by manufacturer (a `YubiHSM` is no `YubiKey`).
    #[test]
    fn a_code_family_never_resolves_to_its_data() {
        let set: &'static Set = Box::leak(Box::new(Set::embedded().unwrap()));
        let bare = Registry::new();
        let maker = |family: &str| {
            let profiles = set.module_family_names();
            assert!(profiles.contains(&family), "{family}: no profile family of that name");
            let p = set.all().iter().find(|p| p.family() == family).unwrap();
            p.r#match.manufacturer.clone().unwrap()
        };
        for family in CODE_FAMILIES {
            let e = bare.select_in(set, Some(family), &module("x")).err();
            assert!(matches!(e, Some(KmError::Validation(_))), "{family} named: {e:?}");
            let detected = bare.select_in(set, None, &module(&maker(family))).err();
            assert!(matches!(detected, Some(KmError::Validation(_))), "{family} detected: {detected:?}");
            let declined = Registry::new().with(Declines(family));
            assert_eq!(declined.select_in(set, None, &module(&maker(family))).unwrap().name(), "generic", "{family}");
            assert_eq!(declined.select_in(set, Some(family), &module("x")).unwrap().name(), family);
        }
        // A family no code claims still resolves to its data.
        assert_eq!(bare.select_in(set, None, &module("SoftHSM")).unwrap().name(), "softhsm");
    }

    #[test]
    fn selection_explicit_then_detected_then_generic() {
        Set::activate_embedded().unwrap();
        let r = Registry::new().with(Acme);
        assert_eq!(r.select(None, &module("Acme")).unwrap().name(), "acme");
        assert_eq!(r.select(None, &module("Other")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("generic"), &module("Acme")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("acme"), &module("Other")).unwrap().name(), "acme");
        assert!(matches!(r.select(Some("nope"), &module("Acme")), Err(KmError::Validation(_))));
        assert!(r.named("acme").unwrap().is_some() && r.named("generic").unwrap().is_some());
        assert!(r.named("ykcs11").is_err(), "a code family this registry lacks");
        assert!(r.named("nope").unwrap().is_none());
    }

    /// A module no code claims is named by its profiles' family; code providers come first, a
    /// family is selectable by name, and two families claiming one manufacturer are refused.
    #[test]
    fn profiles_name_the_modules_code_does_not_claim() {
        let set: &'static Set = Box::leak(Box::new(Set::embedded().unwrap()));
        let r = Registry::new().with(Acme);
        assert_eq!(r.select_in(set, None, &module("SoftHSM")).unwrap().name(), "softhsm");
        assert_eq!(r.select_in(set, None, &module("Kryoptic")).unwrap().name(), "kryoptic");
        // A code family's manufacturer, without its code: refused (B-7).
        assert!(r.select_in(set, None, &module("CloudHSM")).is_err());
        // A layer's manufacturer (p11-kit's) names no module.
        assert_eq!(r.select_in(set, None, &module("PKCS#11 Kit")).unwrap().name(), "generic");
        assert_eq!(r.select_in(set, Some("softhsm"), &module("PKCS#11 Kit")).unwrap().name(), "softhsm");
        assert!(r.select_in(set, Some("aws-cloudhsm"), &module("Other")).is_err());
        // A provider is a family: one module profile's name is none (keys.toml's moduleProfile).
        let pair = Some("aws-cloudhsm/5.18+hsm2m-non-fips");
        assert!(r.select_in(set, pair, &module("CloudHSM")).is_err());
        let e = r.select_in(set, Some("nope"), &module("x")).err().unwrap();
        assert!(e.to_string().contains("profile families: aws-cloudhsm"), "{e}");
        // The same, with no code family in the way.
        assert_eq!(r.select_in(set, Some("kryoptic"), &module("Other")).unwrap().name(), "kryoptic");
        // Code before data: a provider claiming SoftHSM's manufacturer wins.
        assert_eq!(Registry::new().with(Mine).select_in(set, None, &module("SoftHSM")).unwrap().name(), "mine");
        let dir = std::env::temp_dir().join(format!("cakeys-provider-twins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("t.toml"),
            "profile = \"twin/1\"\nmode = \"observed\"\n[match]\nmanufacturer = \"SoftHSM\"\n",
        )
        .unwrap();
        let twins: &'static Set = Box::leak(Box::new(Set::embedded().unwrap().adding_dir(&dir).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
        let e = r.select_in(twins, None, &module("SoftHSM")).err().unwrap();
        assert!(e.to_string().contains("several families (softhsm, twin)"), "{e}");
        assert_eq!(r.select_in(twins, Some("twin"), &module("SoftHSM")).unwrap().name(), "twin");
    }
}
