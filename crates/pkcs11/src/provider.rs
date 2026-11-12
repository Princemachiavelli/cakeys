//! Module-specific behaviour. The generic PKCS#11 code calls these hooks; a provider crate
//! overrides only what its module gets wrong. Every fix-up must return exactly what a
//! spec-compliant module would, so identities stay portable across modules and versions.

use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use cakeys_core::config::{ModuleInfo, ObjectCfg, TokenCfg};
use cakeys_core::{KmError, Result};
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
    fn attest(&self, _ctx: &AttestCtx<'_>) -> Result<Attested> {
        // Unreachable in practice: the caller checks `attestation()` first. Kept as an error so
        // a provider advertising a capability must actually implement it.
        Err(KmError::Unsupported(format!("{} exposes no attestation", self.name())))
    }
}

/// What a provider can attest (§3.7 of docs/DESIGN.md), from [`Provider::attestation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationCap {
    /// Scheme the commitment records (one of `cakeys_core::id::ATTESTATION_SCHEMES`; its
    /// lock-record kind is `cakeys_core::id::attestation_kind`).
    pub scheme: &'static str,
    /// Object classes (`"CKO_PRIVATE_KEY"`, ...) the attestation covers.
    pub classes: &'static [&'static str],
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
    pub fn required_spki(&self) -> Result<Option<&[u8]>> {
        match (self.object.class.as_str(), self.spki) {
            ("CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY", None) => Err(KmError::Unsupported(format!(
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
    pub scheme: &'static str,
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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, p: impl Provider + 'static) -> Self {
        self.providers.push(Arc::new(p));
        self
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Whether `name` is a provider this registry can select explicitly.
    pub fn knows(&self, name: &str) -> bool {
        name == Generic.name() || self.providers.iter().any(|p| p.name() == name)
    }

    /// The explicitly configured provider, else the first registered one that recognises the
    /// module, else [`Generic`].
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
        Ok(self
            .providers
            .iter()
            .find(|p| p.matches(module))
            .cloned()
            .unwrap_or_else(|| Arc::new(Generic)))
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
