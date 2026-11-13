//! Module-specific behaviour. The generic PKCS#11 code calls these hooks; a provider crate
//! overrides only what its module gets wrong. Every fix-up must return exactly what a
//! spec-compliant module would, so identities stay portable across modules and versions.

use cakeys_core::config::{Locator, ModuleInfo, ObjectCfg, Options, TokenCfg};
use cakeys_core::id::Scheme;
use cakeys_core::migrate::Side;
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use std::borrow::Cow;
use std::sync::Arc;

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

    /// `Some(advice)` when the module's `C_DestroyObject` reports success but leaves the key on
    /// the device (ykcs11 only clears the slot's certificate): deleting is then refused (15)
    /// instead of claimed, and the advice names how to remove the key.
    fn keeps_destroyed_keys(&self, _loc: &Locator) -> Option<String> {
        None
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

    /// What this module can do to move keys (MIGRATE.md): which side of an export or import it
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
pub struct AttestCtx<'a> {
    pub session: &'a Session,
    pub cfg: &'a TokenCfg,
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

/// Registered providers. The CLI builds one from the provider crates it links; a downstream
/// binary adds its own with [`Registry::with`] (see the `custom-provider` example).
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

    /// The provider registered as `name` (or [`Generic`]), without loading any module.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<Arc<dyn Provider>> {
        if name == Generic.name() {
            return Some(Arc::new(Generic));
        }
        self.providers.iter().find(|p| p.name() == name).cloned()
    }

    /// The explicitly configured provider, else the first registered one that recognises the
    /// module, else [`Generic`].
    ///
    /// # Errors
    ///
    /// `Validation` when `explicit` names a provider this registry does not have.
    pub fn select(&self, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        if let Some(name) = explicit {
            if name == Generic.name() {
                return Ok(Arc::new(Generic));
            }
            return self.providers.iter().find(|p| p.name() == name).cloned().ok_or_else(|| {
                KmError::Validation(format!(
                    "unknown provider '{name}' (registered: generic, {})",
                    self.names().join(", ")
                ))
            });
        }
        Ok(self.providers.iter().find(|p| p.matches(module)).cloned().unwrap_or_else(|| Arc::new(Generic)))
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

    fn module(manufacturer: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
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
}
