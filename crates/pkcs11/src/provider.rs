//! Module-specific behaviour. The generic PKCS#11 code calls these hooks; a provider crate
//! overrides only what its module gets wrong. Every fix-up must return exactly what a
//! spec-compliant module would, so identities stay portable across modules and versions.

use cakeys_core::config::{Binding, Locator, ModuleInfo, ObjectCfg, Options, SpecCfg, TokenCfg};
use cakeys_core::id::Scheme;
use cakeys_core::migrate::Side;
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
use cakeys_profile::Set;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectHandle};
use cryptoki::session::Session;
use std::borrow::Cow;
use std::sync::Arc;

/// A key bound to one purpose at creation ([`Provider::bound_keys`]).
pub struct BoundKey {
    /// The module's name for the binding (a Cloud KMS algorithm), for notes.
    pub name: String,
    /// `CKA_LABEL`, part of `template`.
    pub label: String,
    /// The PKCS#11 key type it makes: `CKK_EC`, `CKK_RSA`, `CKK_AES`, ...
    pub kind: String,
    /// Its curve name, or its size in bits.
    pub on: String,
    /// The generation mechanism (parameterless).
    pub keygen: MechanismType,
    /// The whole template: the private or secret half's; no public template is passed.
    pub template: Vec<Attribute>,
    /// The mechanisms a key with this binding serves; nothing else is tried on it.
    pub mechanisms: Vec<MechanismType>,
}

/// A key the module generates from its own template ([`Provider::generation`]): `keygen`
/// (parameterless) with `template` alone, the private or secret half's; a pair passes no public
/// template.
pub struct Generation {
    pub keygen: MechanismType,
    pub template: Vec<Attribute>,
}

/// The parameterless generation mechanism `keygen` names, and whether it makes a key pair:
/// what a module-chosen generation ([`Generation`], [`BoundKey`]) runs. `None` for any other.
#[must_use]
pub fn keygen_mechanism(keygen: MechanismType) -> Option<(Mechanism<'static>, bool)> {
    Some(match keygen {
        MechanismType::ECC_KEY_PAIR_GEN => (Mechanism::EccKeyPairGen, true),
        MechanismType::RSA_PKCS_KEY_PAIR_GEN => (Mechanism::RsaPkcsKeyPairGen, true),
        MechanismType::AES_KEY_GEN => (Mechanism::AesKeyGen, false),
        MechanismType::GENERIC_SECRET_KEY_GEN => (Mechanism::GenericSecretKeyGen, false),
        _ => return None,
    })
}

pub trait Provider: Send + Sync {
    /// Name for `provider = "<name>"` in keys.toml and in messages.
    fn name(&self) -> &'static str;

    /// Whether this provider recognises the loaded module (from `C_GetInfo`), for auto-detection.
    fn matches(&self, module: &ModuleInfo) -> bool;

    /// The mechanisms to rely on. Override to drop ones the module advertises but cannot use.
    fn mechanisms(&self, advertised: Vec<MechanismType>) -> Vec<MechanismType> {
        advertised
    }

    /// Repair a module's `CKA_EC_POINT` encoding.
    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(raw)
    }

    /// Repair a boolean policy attribute (`CKA_SIGN`, `CKA_DERIVE`, ...) the module misreports:
    /// `reported` is what it returned for `attr`, `private_key_type` reads the object's key type
    /// when it is a private key. The policy check and the lock's recorded policy both see the
    /// result, so it must be what a spec-compliant module would report (ykcs11's fixed table
    /// says `CKA_DERIVE` false on keys its `C_DeriveKey` derives with). The profile keeps the
    /// raw observation (`derive.key-attribute`).
    fn policy_flag(
        &self,
        _attr: AttributeType,
        reported: bool,
        _private_key_type: &dyn Fn() -> Option<KeyType>,
    ) -> bool {
        reported
    }

    /// Advice appended when the module cannot do something the spec asks for.
    fn hint(&self) -> Option<&'static str> {
        None
    }

    /// Check `token`'s `[tokens.<t>.options]` when it is opened: a provider with settings parses
    /// them (`cakeys_core::config::parse_options`, unknown names refused); the default takes none,
    /// so any option is refused (17) rather than silently ignored.
    ///
    /// # Errors
    ///
    /// `Validation` for any option on a provider that takes none; a provider with settings
    /// adds whatever its own parsing refuses.
    fn check_options(&self, token: &str, options: &Options) -> Result<()> {
        match options.keys().next() {
            None => Ok(()),
            Some(k) => Err(KmError::Validation(format!(
                "tokens.{token}.options.{k}: provider {} takes no options",
                self.name()
            ))),
        }
    }

    /// Whether the module creates and destroys token objects only in a Security Officer session
    /// (ykcs11: the PIV management key). Then `tokens.<t>.mgmKeyFile`/`mgmKeyEnv` is used for exactly those
    /// steps; elsewhere it is refused, since an SO there cannot do what the user does.
    fn manages_as_so(&self) -> bool {
        false
    }

    /// Refuse a generation the module would carry out somewhere other than under `loc`, before
    /// anything is created (ykcs11 places the key by `CKA_ID` and ignores `CKA_LABEL`).
    ///
    /// # Errors
    ///
    /// `Unsupported` when the locator cannot name where the module will actually put the key.
    fn check_create(&self, _object: &ObjectCfg, _loc: &Locator) -> Result<()> {
        Ok(())
    }

    /// The keys a module binds to one purpose when it creates them (Google Cloud KMS: one
    /// algorithm per key), each with the exact template it is generated from: the write probe
    /// generates these instead of its own templates. Empty for a module whose keys are general
    /// purpose, the default.
    fn bound_keys(&self) -> Vec<BoundKey> {
        Vec::new()
    }

    /// The module's own generation of `object` as `spec` declares it under `loc`, to be proven
    /// by `binding` (private keys): `None` for cakeys' own templates, the default. A module that
    /// takes only its own template (Google Cloud KMS) chooses it here, and refuses here, before
    /// anything is created, what would become a key cakeys could not then identify or prove: a
    /// key it destroys again is not always gone (Cloud KMS keeps the label for good).
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) for an object the module cannot make as declared; `Validation` (17)
    /// for a locator it cannot place a key under.
    fn generation(
        &self,
        _object: &ObjectCfg,
        _spec: &SpecCfg,
        _loc: &Locator,
        _binding: Option<Binding>,
    ) -> Result<Option<Generation>> {
        Ok(None)
    }

    /// `Some(advice)` when the module's `C_DestroyObject` reports success but leaves the key on
    /// the device (ykcs11 only clears the slot's certificate): deleting is then refused (15)
    /// instead of claimed, and the advice names how to remove the key.
    fn keeps_destroyed_keys(&self, _loc: &Locator) -> Option<String> {
        None
    }

    /// Whether the certificates `certs` (DER) found under the probe's scratch `CKA_ID` (`id`)
    /// show a slot holding only what this module itself wrote when it generated the slot's key —
    /// the only occupant the write probe may replace (`tokens.<t>.scratchId`). Anything else may
    /// be a real key, so the probe refuses it. The default recognises none.
    fn scratch_occupant(&self, _id: &[u8], _certs: &[Vec<u8>]) -> bool {
        false
    }

    /// The attestation commitment this provider can compute (§3.7 of docs/DESIGN.md), if any:
    /// the scheme it records and the object classes it can attest.
    /// `None` (the default): this module exposes no attestation, so a spec opting into one is
    /// refused (15) before anything is created.
    fn attestation(&self) -> Option<AttestationCap> {
        None
    }

    /// Compute the attestation commitment for `key` on its token (called only when the spec
    /// opted in and [`Provider::attestation`] covers the class). Returns the canonical scheme
    /// digest plus the anchor it was verified to. A missing attestation is an error naming the
    /// reason (e.g. an imported key, or a session that could not attest), never a pass; an
    /// attestation that names other material than `ctx.spki` is a conflict (13).
    ///
    /// # Errors
    ///
    /// Whatever the module's attestation path cannot establish: `Unsupported` (this default:
    /// the provider advertises none), `Unavailable` when the token has none to give, `Conflict`
    /// when it names other material than `ctx.spki`.
    fn attest(&self, _ctx: &AttestCtx<'_>) -> Result<Attested> {
        // Unreachable in practice: the caller checks `attestation()` first. Kept as an error so
        // a provider advertising a capability must actually implement it.
        Err(KmError::Unsupported(format!("{} exposes no attestation", self.name())))
    }

    /// Import plaintext key material the module's own way, outside PKCS#11 (docs/CAMIGRATE.md
    /// `tpm2-ptool`: tpm2-pkcs11 creates keys from values only through `tpm2_ptool import`):
    /// `ctx.key` is a private key's PKCS#8 `PrivateKeyInfo` or a secret key's value. The caller
    /// opens the token again afterwards to see the key. The default refuses.
    ///
    /// # Errors
    ///
    /// `Unsupported` (this default, or a key type the tool cannot take); whatever the tool
    /// reports.
    fn import_plaintext(&self, _ctx: &ImportCtx<'_>) -> Result<()> {
        Err(KmError::Unsupported(format!("{} imports no plaintext outside PKCS#11", self.name())))
    }

    /// What this module can do to move keys (docs/CAMIGRATE.md): which side of an export or import it
    /// can be, through which mechanisms, and any methods of its own (`Side::vendor`, D10). The
    /// default is a spec-compliant PKCS#11 module: it wraps and unwraps with what it lists and
    /// imports with `C_CreateObject`.
    fn migration(&self, token: &str, mechanisms: &[String]) -> Side {
        Side::pkcs11(token, self.name(), mechanisms.iter().cloned())
    }
}

/// What a provider can attest (§3.7 of docs/DESIGN.md), from [`Provider::attestation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationCap {
    /// Scheme the commitment records (an attestation scheme: `Scheme::is_attestation`; its
    /// lock-record kind is `Scheme::attestation_kind`).
    pub scheme: Scheme,
    /// Object classes the attestation covers.
    pub classes: &'static [ObjectClass],
}

/// Everything an attestation may need beyond the PKCS#11 module: the session (to find the
/// certificate objects a module exposes), the config (the native TPM path's TCTI and store) and
/// the PIN (the TPM path unseals the token's wrapping key with it), plus the material SPKI the
/// attestation must name (`None` exactly for secret keys, which have none).
///
/// `provision` is true only under `realise`: a provider that keeps device state to attest with
/// (the TPM Attestation Key) may create it then, never on a read (`resolve`, `verify`).
/// What [`Provider::import_plaintext`] gets: the token as keys.toml describes it, the key's type
/// and locator, and the plaintext. Never `Debug`: it would print the key and the PIN.
pub struct ImportCtx<'a> {
    pub cfg: &'a TokenCfg,
    pub token_name: &'a str,
    pub pin: Option<&'a str>,
    pub object: &'a ObjectCfg,
    pub locator: &'a Locator,
    pub key: &'a [u8],
}

pub struct AttestCtx<'a> {
    pub session: &'a Session,
    pub cfg: &'a TokenCfg,
    /// The module's version as `C_GetInfo` reports it ("1.10").
    pub module_version: &'a str,
    pub token_name: &'a str,
    pub key: ObjectHandle,
    pub object: &'a ObjectCfg,
    pub spki: Option<&'a [u8]>,
    pub pin: Option<&'a str>,
    pub provision: bool,
}

impl AttestCtx<'_> {
    /// The material SPKI, required for asymmetric classes: an attestation that could not be
    /// cross-checked against the key `rfc7093m4` names would be provenance for unknown material.
    ///
    /// # Errors
    ///
    /// `Unsupported` when an asymmetric class has no SPKI to check against.
    pub fn required_spki(&self) -> Result<Option<&[u8]>> {
        match (self.object.class, self.spki) {
            (c, None) if c.is_asymmetric() => Err(KmError::Unsupported(format!(
                "attesting a {} needs its material SPKI to cross-check against",
                self.object.class
            ))),
            (_, spki) => Ok(spki),
        }
    }
}

/// A computed attestation commitment (§3.7 of docs/DESIGN.md): the scheme digest plus the
/// anchor the attestation was verified against — recorded in the lock as the realisation's
/// `attestation = { kind, root, id }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub scheme: Scheme,
    pub id: String,
    pub root: String,
}

/// Plain PKCS#11, used when no registered provider recognises the module.
pub struct Generic;

impl Provider for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        true
    }
}

/// A module that needs no code of its own (docs/CAPROBE.md: no Rust for a module without
/// fix-ups): recognised by the `[match] manufacturer` of its module profiles, named by their
/// family, every hook the default. `softhsm`, `kryoptic` and `aws-cloudhsm` are these.
pub struct Data(&'static str);

impl Provider for Data {
    fn name(&self) -> &'static str {
        self.0
    }

    /// Never asked: the registry detects data providers from the profiles, not one by one.
    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }
}

/// Registered providers. The CLI builds one from the provider crates it links; a downstream
/// binary adds its own with [`Registry::with`] (see the `custom-provider` example). A module
/// profile's family is a provider too ([`Data`]), with no code: the registry falls back to the
/// profiles when no code provider is named or claims a module.
#[derive(Clone, Default)]
pub struct Registry {
    providers: Vec<Arc<dyn Provider>>,
}

impl Registry {
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

    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Whether `name` is a provider this registry can select explicitly.
    #[must_use]
    pub fn knows(&self, name: &str) -> bool {
        self.named(name).is_some()
    }

    /// The provider registered as `name` (or [`Generic`]), else the module profile family of
    /// that name ([`Data`]), without loading any module.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<Arc<dyn Provider>> {
        Set::active().ok().and_then(|set| self.named_in(set, name))
    }

    fn named_in(&self, set: &'static Set, name: &str) -> Option<Arc<dyn Provider>> {
        if name == Generic.name() {
            return Some(Arc::new(Generic));
        }
        if let Some(p) = self.providers.iter().find(|p| p.name() == name) {
            return Some(Arc::clone(p));
        }
        // A module profile's own name (`aws-cloudhsm/5.18+hsm2m-non-fips`): its family's
        // provider, and the resolution takes that profile alone (profiles that tie on every
        // match key, as a FIPS and a non-FIPS cluster do).
        if let Some((family, _)) = name.split_once('/') {
            let known = set.all().iter().any(|p| p.mode == cakeys_profile::Mode::Observed && p.profile == name);
            return if known { self.named_in(set, family) } else { None };
        }
        let family = set.module_family_names().into_iter().find(|f| *f == name)?;
        Some(Arc::new(Data(family)))
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
        self.select_in(Set::active().map_err(KmError::Validation)?, explicit, module)
    }

    fn select_in(&self, set: &'static Set, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        if let Some(name) = explicit {
            return self.named_in(set, name).ok_or_else(|| {
                KmError::Validation(format!(
                    "unknown provider '{name}' (registered: generic, {}; profile families: {})",
                    self.names().join(", "),
                    set.module_family_names().join(", ")
                ))
            });
        }
        if let Some(p) = self.providers.iter().find(|p| p.matches(module)) {
            return Ok(Arc::clone(p));
        }
        let manufacturer = module.manufacturer.trim_end_matches([' ', '\0']);
        match set.module_families(manufacturer)[..] {
            [] => Ok(Arc::new(Generic)),
            [family] => Ok(Arc::new(Data(family))),
            ref families => Err(KmError::Validation(format!(
                "the module's manufacturer '{manufacturer}' is claimed by the profiles of several families \
                 ({}): name one in `provider`",
                families.join(", ")
            ))),
        }
    }
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

    #[test]
    fn selection_explicit_then_detected_then_generic() {
        let r = Registry::new().with(Acme);
        assert_eq!(r.select(None, &module("Acme")).unwrap().name(), "acme");
        assert_eq!(r.select(None, &module("Other")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("generic"), &module("Acme")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("acme"), &module("Other")).unwrap().name(), "acme");
        assert!(matches!(r.select(Some("nope"), &module("Acme")), Err(KmError::Validation(_))));
        assert!(r.knows("acme") && r.knows("generic") && !r.knows("nope"));
    }

    /// A module no code claims is named by its profiles' family; code providers come first, a
    /// family is selectable by name, and two families claiming one manufacturer are refused.
    #[test]
    fn profiles_name_the_modules_code_does_not_claim() {
        let set: &'static Set = Box::leak(Box::new(Set::embedded().unwrap()));
        let r = Registry::new().with(Acme);
        assert_eq!(r.select_in(set, None, &module("SoftHSM")).unwrap().name(), "softhsm");
        assert_eq!(r.select_in(set, None, &module("Kryoptic")).unwrap().name(), "kryoptic");
        assert_eq!(r.select_in(set, None, &module("CloudHSM")).unwrap().name(), "aws-cloudhsm");
        // A layer's manufacturer (p11-kit's) names no module.
        assert_eq!(r.select_in(set, None, &module("PKCS#11 Kit")).unwrap().name(), "generic");
        assert_eq!(r.select_in(set, Some("softhsm"), &module("PKCS#11 Kit")).unwrap().name(), "softhsm");
        assert_eq!(r.select_in(set, Some("aws-cloudhsm"), &module("Other")).unwrap().name(), "aws-cloudhsm");
        // A module profile's own name selects its family; a name no profile has, nothing.
        let pair = Some("aws-cloudhsm/5.18+hsm2m-non-fips");
        assert_eq!(r.select_in(set, pair, &module("CloudHSM")).unwrap().name(), "aws-cloudhsm");
        assert!(r.select_in(set, Some("aws-cloudhsm/9.9"), &module("CloudHSM")).is_err());
        let e = r.select_in(set, Some("nope"), &module("x")).err().unwrap();
        assert!(e.to_string().contains("profile families: aws-cloudhsm"), "{e}");
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
