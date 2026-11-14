//! Export and import planning (MIGRATE.md): which method can move an object from one token to
//! another, at which exposure, and why not when it cannot. Pure: the facts come from the lock
//! (the object's type, the source realisation's policy) and from each side's capabilities (a
//! [`Side`], built by the token's provider), so `--dry-run` and the real run share this one
//! decision (MIGRATE.md D9).

use crate::config::{AttrValue, Immutables, ObjectCfg};
use crate::pop::OaepHash;
use crate::types::{KeyType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How much of the material is exposed on the way (MIGRATE.md D2), strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    /// Nothing secret moves.
    Public,
    /// Sealed, and the source token accepts no other wrapping key (`CKA_WRAP_WITH_TRUSTED`).
    Enforced,
    /// Leaves the source only wrapped under a key on the target.
    Sealed,
    /// In plaintext in cakeys' memory, zeroized after; never on disk.
    Host,
    /// A passphrase-protected file.
    File,
}

impl Exposure {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Exposure::Public => "public",
            Exposure::Enforced => "enforced",
            Exposure::Sealed => "sealed",
            Exposure::Host => "host",
            Exposure::File => "file",
        }
    }
}

impl std::fmt::Display for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A passphrase-protected file format for targets cakeys cannot reach (`file` exposure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// PKCS#8 `EncryptedPrivateKeyInfo` (PBES2).
    Pkcs8,
    /// PKCS#12, the key with its certificate.
    Pkcs12,
}

/// How an object moves. The names are frozen like scheme names (MIGRATE.md, "Frozen names and
/// formats"): a bundle or a lock's `provenance.origin` written with one must keep meaning it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Public,
    /// A fresh AES KEK under RSA-OAEP to the transport key, the key under the KEK (RFC 5649).
    RsaOaepAesKwp(OaepHash),
    /// The key under RSA-OAEP to the transport key directly (small secret keys).
    RsaOaep(OaepHash),
    /// Through the host, into a PKCS#11 target with `C_CreateObject`.
    HostPkcs8,
    HostRaw,
    /// Through the host, then `tpm2_ptool import`.
    Tpm2Ptool,
    /// Through the host, then ykcs11 `C_CreateObject` as SO.
    PivImport,
    /// A duplication blob built on the host for the target TPM's parent key.
    TpmDuplicate,
    Pkcs8Pbes2,
    Pkcs12,
    /// A provider's own method (MIGRATE.md D10).
    Vendor {
        provider: String,
        name: String,
    },
}

impl Method {
    /// The frozen name, as a bundle and the lock write it.
    #[must_use]
    pub fn name(&self) -> String {
        let oaep = |h: &OaepHash| match h {
            OaepHash::Sha1 => "rsa-oaep-sha1",
            OaepHash::Sha256 => "rsa-oaep-sha256",
        };
        match self {
            Method::Public => "public".into(),
            Method::RsaOaepAesKwp(h) => format!("{}+aes-kwp", oaep(h)),
            Method::RsaOaep(h) => oaep(h).into(),
            Method::HostPkcs8 => "host-pkcs8".into(),
            Method::HostRaw => "host-raw".into(),
            Method::Tpm2Ptool => "tpm2-ptool".into(),
            Method::PivImport => "piv-import".into(),
            Method::TpmDuplicate => "tpm-duplicate".into(),
            Method::Pkcs8Pbes2 => "pkcs8-pbes2".into(),
            Method::Pkcs12 => "pkcs12".into(),
            Method::Vendor { provider, name } => format!("vendor:{provider}/{name}"),
        }
    }

    /// The method a frozen name denotes; `None` for a name this cakeys does not know.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Method> {
        if let Some(rest) = name.strip_prefix("vendor:") {
            let (provider, name) = rest.split_once('/')?;
            return (!provider.is_empty() && !name.is_empty())
                .then(|| Method::Vendor { provider: provider.into(), name: name.into() });
        }
        Method::BUILTIN.iter().find(|m| m.name() == name).cloned()
    }

    /// Every built-in method, for name lookups and the pinning test.
    pub const BUILTIN: [Method; 12] = [
        Method::Public,
        Method::RsaOaepAesKwp(OaepHash::Sha256),
        Method::RsaOaepAesKwp(OaepHash::Sha1),
        Method::RsaOaep(OaepHash::Sha256),
        Method::RsaOaep(OaepHash::Sha1),
        Method::HostPkcs8,
        Method::HostRaw,
        Method::Tpm2Ptool,
        Method::PivImport,
        Method::TpmDuplicate,
        Method::Pkcs8Pbes2,
        Method::Pkcs12,
    ];
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

/// Which objects a capability covers: a class, and optionally only some key types, curves or
/// RSA sizes (empty: any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accept {
    pub class: ObjectClass,
    pub key_types: Vec<KeyType>,
    pub curves: Vec<&'static str>,
    /// Inclusive RSA modulus range in bits.
    pub modulus_bits: Option<(u32, u32)>,
}

impl Accept {
    #[must_use]
    pub fn class(class: ObjectClass) -> Accept {
        Accept { class, key_types: vec![], curves: vec![], modulus_bits: None }
    }

    #[must_use]
    pub fn key(class: ObjectClass, key_types: &[KeyType]) -> Accept {
        Accept { key_types: key_types.to_vec(), ..Accept::class(class) }
    }

    #[must_use]
    pub fn covers(&self, ty: &ObjectCfg) -> bool {
        self.class == ty.class
            && (self.key_types.is_empty() || ty.key_type.is_some_and(|k| self.key_types.contains(&k)))
            && (self.curves.is_empty() || ty.curve.as_deref().is_some_and(|c| self.curves.contains(&c)))
            && match (self.modulus_bits, ty.modulus_bits) {
                (Some((lo, hi)), Some(bits)) => (u64::from(lo)..=u64::from(hi)).contains(&bits),
                (Some(_), None) => false,
                (None, _) => true,
            }
    }
}

/// How plaintext material gets into a token (the `host` paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaintextImport {
    /// `C_CreateObject` with the key's attributes (any PKCS#11 module that accepts it).
    CreateObject,
    /// `tpm2_ptool import`, for the listed objects.
    Tpm2Ptool(Vec<Accept>),
    /// ykcs11 `C_CreateObject` as SO into a PIV slot, for the listed objects.
    PivImport(Vec<Accept>),
}

/// A provider's own method (MIGRATE.md D10): its name, the exposure it declares, what it moves,
/// and the target providers it works with (empty: any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorMethod {
    pub provider: String,
    pub name: String,
    pub exposure: Exposure,
    pub objects: Vec<Accept>,
    pub targets: Vec<String>,
}

/// One token's capabilities for moving keys, as its provider describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    pub token: String,
    pub provider: String,
    /// The usable mechanisms (provider-filtered), by `CKM_*` name.
    pub mechanisms: BTreeSet<String>,
    /// Whether the module ever wraps a key out (`C_WrapKey`).
    pub exports: bool,
    /// Whether the module unwraps a key in (`C_UnwrapKey`).
    pub unwraps: bool,
    /// The OAEP hashes the module implements for wrapping, not only lists.
    pub oaep: Vec<OaepHash>,
    /// Public objects it accepts from their value or DER.
    pub public_import: Vec<Accept>,
    /// How plaintext private and secret keys get in, if at all.
    pub plaintext_import: Option<PlaintextImport>,
    /// Provider methods this side offers as a source (MIGRATE.md D10).
    pub vendor: Vec<VendorMethod>,
}

impl Side {
    /// A spec-compliant PKCS#11 module: wraps and unwraps with what it lists, imports public
    /// objects and plaintext keys with `C_CreateObject`.
    #[must_use]
    pub fn pkcs11(token: &str, provider: &str, mechanisms: impl IntoIterator<Item = String>) -> Side {
        Side {
            token: token.into(),
            provider: provider.into(),
            mechanisms: mechanisms.into_iter().collect(),
            exports: true,
            unwraps: true,
            oaep: vec![OaepHash::Sha1, OaepHash::Sha256],
            public_import: [ObjectClass::Certificate, ObjectClass::PublicKey, ObjectClass::Data]
                .into_iter()
                .map(Accept::class)
                .collect(),
            plaintext_import: Some(PlaintextImport::CreateObject),
            vendor: vec![],
        }
    }

    fn has(&self, mechanism: &str) -> bool {
        self.mechanisms.contains(mechanism)
    }

    /// RFC 5649, under either PKCS#11 name (the same format, MIGRATE.md spike).
    fn kwp(&self) -> bool {
        self.has("CKM_AES_KEY_WRAP_KWP") || self.has("CKM_AES_KEY_WRAP_PAD")
    }
}

/// Where the material goes.
#[derive(Debug, Clone)]
pub enum To<'a> {
    Token(&'a Side),
    File(FileFormat),
}

/// What the planner knows about the object: its type (from the lock) and the source
/// realisation's recorded policy and immutables.
#[derive(Debug, Clone, Copy)]
pub struct Material<'a> {
    pub object: &'a str,
    pub ty: &'a ObjectCfg,
    pub policy: &'a BTreeMap<String, AttrValue>,
    pub immutables: &'a Immutables,
}

impl Material<'_> {
    fn flag(&self, name: &str) -> Option<bool> {
        match self.policy.get(name) {
            Some(AttrValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// What the caller allows.
#[derive(Debug, Clone, Copy, Default)]
pub struct Allow {
    /// `--allow-host-plaintext`: the `host` and `file` paths.
    pub host_plaintext: bool,
    /// The transport key is marked `CKA_TRUSTED` on the source (phase 3b).
    pub trusted_transport: bool,
}

/// The decision for one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub object: String,
    /// The method that would be used, also when a flag is missing; `None` when nothing fits.
    #[serde(serialize_with = "method_name")]
    pub method: Option<Method>,
    pub exposure: Option<Exposure>,
    /// Whether it can run as invoked.
    pub ready: bool,
    /// Why not (or what is missing), when not ready.
    pub reasons: Vec<String>,
    /// What changes on the way (attestation, a declared vendor level, ...).
    pub notes: Vec<String>,
}

#[expect(clippy::ref_option, reason = "serde's serialize_with hands the field by reference")]
fn method_name<S: serde::Serializer>(m: &Option<Method>, s: S) -> Result<S::Ok, S::Error> {
    match m {
        Some(m) => s.serialize_str(&m.name()),
        None => s.serialize_none(),
    }
}

impl Plan {
    fn ready(m: &Material, method: Method, exposure: Exposure, notes: Vec<String>) -> Plan {
        Plan {
            object: m.object.into(),
            method: Some(method),
            exposure: Some(exposure),
            ready: true,
            reasons: vec![],
            notes,
        }
    }

    fn impossible(m: &Material, reasons: Vec<String>) -> Plan {
        Plan { object: m.object.into(), method: None, exposure: None, ready: false, reasons, notes: vec![] }
    }
}

/// Decide how `m` moves from `from` to `to`, strongest exposure first: a provider method that
/// declares a stronger level, then the built-ins. A method that needs a flag the caller did not
/// give is still named, with `ready = false` and the flag in `reasons`.
#[must_use]
pub fn plan(m: &Material, from: &Side, to: &To, allow: Allow) -> Plan {
    let ty = m.ty;
    if is_public(ty) {
        return match to {
            To::Token(dst) if dst.public_import.iter().any(|a| a.covers(ty)) => {
                Plan::ready(m, Method::Public, Exposure::Public, vec![])
            }
            To::Token(dst) => Plan::impossible(m, vec![format!("{} accepts no {} by import", dst.token, describe(ty))]),
            To::File(_) => {
                Plan::impossible(m, vec!["files carry private keys; a public object needs no export".into()])
            }
        };
    }
    if !from.exports {
        return Plan::impossible(
            m,
            vec![format!("{} ({}) never lets a key leave the token", from.token, from.provider)],
        );
    }
    if m.flag("CKA_EXTRACTABLE") != Some(true) || m.immutables.never_extractable == Some(true) {
        return Plan::impossible(
            m,
            vec!["not extractable: exportability is fixed when a key is created (CKA_EXTRACTABLE = false; MIGRATE.md D1)".into()],
        );
    }
    let trusted_only = m.flag("CKA_WRAP_WITH_TRUSTED") == Some(true);
    let mut candidates: Vec<(Method, Exposure, Vec<String>)> = Vec::new();
    // Provider methods compete at their declared level (D10).
    if let To::Token(dst) = to {
        for v in &from.vendor {
            if v.objects.iter().any(|a| a.covers(ty)) && (v.targets.is_empty() || v.targets.contains(&dst.provider)) {
                let method = Method::Vendor { provider: v.provider.clone(), name: v.name.clone() };
                let note =
                    format!("{} declares the {} level; cakeys records it, it cannot check it", method, v.exposure);
                candidates.push((method, v.exposure, vec![note]));
            }
        }
    }
    let mut blocked: Vec<String> = Vec::new();
    match to {
        To::Token(dst) => {
            sealed(m, from, dst, trusted_only, allow, &mut candidates, &mut blocked);
            if trusted_only {
                blocked.push(
                    "CKA_WRAP_WITH_TRUSTED: only a key the source's SO marked trusted may wrap it, so no host path"
                        .into(),
                );
            } else {
                host(m, from, dst, &mut candidates, &mut blocked);
            }
        }
        To::File(format) => {
            if trusted_only {
                blocked.push("CKA_WRAP_WITH_TRUSTED: it cannot be written to a file".into());
            } else if !host_extractable(ty, from) {
                blocked.push(format!("{} offers no AES key wrap to bring it to the host", from.token));
            } else {
                match format {
                    FileFormat::Pkcs8 if ty.class == ObjectClass::PrivateKey => {
                        candidates.push((Method::Pkcs8Pbes2, Exposure::File, vec![]));
                    }
                    FileFormat::Pkcs12 if ty.class == ObjectClass::PrivateKey => {
                        candidates.push((Method::Pkcs12, Exposure::File, vec![]));
                    }
                    _ => blocked.push("PKCS#8 and PKCS#12 files carry private keys".into()),
                }
            }
        }
    }
    candidates.sort_by_key(|(_, e, _)| *e);
    let Some((method, exposure, notes)) = candidates.into_iter().next() else {
        return Plan::impossible(m, blocked);
    };
    let mut plan = Plan::ready(m, method, exposure, notes);
    if matches!(exposure, Exposure::Host | Exposure::File) && !allow.host_plaintext {
        plan.ready = false;
        plan.reasons.push(format!("the {exposure} path needs --allow-host-plaintext (MIGRATE.md D2)"));
    }
    if let To::Token(dst) = to {
        plan.notes.extend(target_notes(dst, &plan));
    }
    plan
}

fn is_public(ty: &ObjectCfg) -> bool {
    matches!(ty.class, ObjectClass::Certificate | ObjectClass::PublicKey | ObjectClass::Data)
}

fn describe(ty: &ObjectCfg) -> String {
    match (ty.key_type, ty.curve.as_deref()) {
        (Some(k), Some(c)) => format!("{} {k} {c}", ty.class),
        (Some(k), None) => format!("{} {k}", ty.class),
        _ => ty.class.to_string(),
    }
}

/// The `sealed` (or `enforced`) methods between two PKCS#11 modules.
fn sealed(
    m: &Material,
    from: &Side,
    dst: &Side,
    trusted_only: bool,
    allow: Allow,
    candidates: &mut Vec<(Method, Exposure, Vec<String>)>,
    blocked: &mut Vec<String>,
) {
    if !dst.unwraps {
        blocked.push(format!("{} ({}) unwraps nothing", dst.token, dst.provider));
        return;
    }
    let exposure = if trusted_only {
        if !allow.trusted_transport {
            blocked.push(
                "CKA_WRAP_WITH_TRUSTED: the transport key must be marked trusted on the source (`transport --trusted`, phase 3b)"
                    .into(),
            );
            return;
        }
        Exposure::Enforced
    } else {
        Exposure::Sealed
    };
    let oaep = [OaepHash::Sha256, OaepHash::Sha1].into_iter().find(|h| {
        from.has("CKM_RSA_PKCS_OAEP") && dst.has("CKM_RSA_PKCS_OAEP") && from.oaep.contains(h) && dst.oaep.contains(h)
    });
    let Some(hash) = oaep else {
        blocked.push(format!("no RSA-OAEP hash both {} and {} implement", from.token, dst.token));
        return;
    };
    if from.kwp() && dst.kwp() && from.has("CKM_AES_KEY_GEN") {
        candidates.push((Method::RsaOaepAesKwp(hash), exposure, vec![]));
    } else if m.ty.class == ObjectClass::SecretKey && m.ty.value_len.is_some_and(|n| n <= OAEP_DIRECT_MAX) {
        candidates.push((Method::RsaOaep(hash), exposure, vec![]));
    } else {
        blocked.push(format!(
            "{} and {} share no RFC 5649 key wrap (CKM_AES_KEY_WRAP_KWP or _PAD) to carry a {}",
            from.token,
            dst.token,
            describe(m.ty)
        ));
    }
}

/// The largest secret key RSA-OAEP carries directly under a 2048-bit transport key with SHA-256
/// (256 - 2 × 32 - 2 bytes); larger transport keys carry more.
const OAEP_DIRECT_MAX: u64 = 190;

/// Whether the source can hand the material to the host: wrapped under a session key cakeys
/// knows, then unwrapped in memory.
fn host_extractable(ty: &ObjectCfg, from: &Side) -> bool {
    match ty.class {
        ObjectClass::SecretKey => from.has("CKM_AES_KEY_WRAP") || from.kwp(),
        _ => from.kwp(),
    }
}

/// The `host` methods into a token.
fn host(
    m: &Material,
    from: &Side,
    dst: &Side,
    candidates: &mut Vec<(Method, Exposure, Vec<String>)>,
    blocked: &mut Vec<String>,
) {
    let ty = m.ty;
    let Some(path) = &dst.plaintext_import else {
        blocked.push(format!("{} ({}) imports no key material", dst.token, dst.provider));
        return;
    };
    if !host_extractable(ty, from) {
        blocked.push(format!("{} offers no AES key wrap to bring it to the host", from.token));
        return;
    }
    let method = match path {
        PlaintextImport::CreateObject if ty.class == ObjectClass::PrivateKey => Method::HostPkcs8,
        PlaintextImport::CreateObject => Method::HostRaw,
        PlaintextImport::Tpm2Ptool(accepts) if accepts.iter().any(|a| a.covers(ty)) => Method::Tpm2Ptool,
        PlaintextImport::PivImport(accepts) if accepts.iter().any(|a| a.covers(ty)) => Method::PivImport,
        PlaintextImport::Tpm2Ptool(_) | PlaintextImport::PivImport(_) => {
            blocked.push(format!("{} ({}) cannot import a {}", dst.token, dst.provider, describe(ty)));
            return;
        }
    };
    candidates.push((method, Exposure::Host, vec![]));
}

/// What the target changes about the object, whatever moves it.
fn target_notes(dst: &Side, plan: &Plan) -> Vec<String> {
    match plan.method {
        Some(Method::PivImport) => {
            vec!["an imported PIV key is never attested; `attestation = true` is refused there".into()]
        }
        Some(Method::Tpm2Ptool | Method::TpmDuplicate) => {
            vec![format!("{} can attest the key's residence, not its generation (CKA_LOCAL = false)", dst.token)]
        }
        Some(Method::Public | Method::Vendor { .. }) | None => vec![],
        Some(_) => vec!["imported, so CKA_LOCAL is false on the target".into()],
    }
}

/// The transport file (`cakeys transport`, MIGRATE.md D3): what a source needs to wrap to a
/// target's transport key without reaching the target: the public key, its locked identity,
/// and the target's provider and mechanisms for planning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub format: String,
    pub version: u32,
    pub token: String,
    pub provider: String,
    pub object: String,
    pub rfc7093m4: String,
    /// Base64 of the canonical SPKI DER.
    pub spki: String,
    pub trusted: bool,
    pub mechanisms: Vec<String>,
}

pub const TRANSPORT_FORMAT: &str = "cakeys-transport";
pub const TRANSPORT_VERSION: u32 = 1;

impl Transport {
    /// The transport file for `object`'s public key on `token`.
    ///
    /// # Errors
    ///
    /// `Validation` when `spki` is not a public key cakeys can canonicalize.
    pub fn new(
        token: &str,
        provider: &str,
        object: &str,
        spki: &[u8],
        mechanisms: &[String],
    ) -> crate::Result<Transport> {
        use base64::Engine;
        let spki = crate::id::spki_canonical(spki)?;
        Ok(Transport {
            format: TRANSPORT_FORMAT.into(),
            version: TRANSPORT_VERSION,
            token: token.into(),
            provider: provider.into(),
            object: object.into(),
            rfc7093m4: crate::id::sri(&spki),
            spki: base64::engine::general_purpose::STANDARD.encode(&spki),
            trusted: false,
            mechanisms: mechanisms.to_vec(),
        })
    }

    /// Read a transport file, checking that its identity is the hash of its public key: a file
    /// edited to wrap to another key fails here, and against the lock (`check_locked`).
    ///
    /// # Errors
    ///
    /// `Validation` for another format or version, malformed base64, or an identity that is not
    /// the public key's.
    pub fn parse(text: &str, path: &std::path::Path) -> crate::Result<Transport> {
        let t: Transport =
            toml::from_str(text).map_err(|e| crate::KmError::Validation(format!("{}: {e}", path.display())))?;
        if t.format != TRANSPORT_FORMAT || t.version != TRANSPORT_VERSION {
            return Err(crate::KmError::Validation(format!(
                "{}: not a {TRANSPORT_FORMAT} version {TRANSPORT_VERSION} file",
                path.display()
            )));
        }
        let computed = crate::id::sri(&t.spki()?);
        if computed != t.rfc7093m4 {
            return Err(crate::KmError::Validation(format!(
                "{}: rfc7093m4 {} is not the identity of its public key ({computed})",
                path.display(),
                t.rfc7093m4
            )));
        }
        Ok(t)
    }

    /// The file's text.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    /// The canonical SPKI DER.
    ///
    /// # Errors
    ///
    /// `Validation` for malformed base64 or a public key cakeys cannot canonicalize.
    pub fn spki(&self) -> crate::Result<Vec<u8>> {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(&self.spki)
            .map_err(|e| crate::KmError::Validation(format!("transport key: {e}")))?;
        crate::id::spki_canonical(&der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(class: ObjectClass, kt: Option<KeyType>) -> ObjectCfg {
        ObjectCfg::new(class, kt)
    }

    fn p256() -> ObjectCfg {
        let mut o = obj(ObjectClass::PrivateKey, Some(KeyType::Ec));
        o.curve = Some("secp256r1".into());
        o
    }

    fn policy(flags: &[(&str, bool)]) -> BTreeMap<String, AttrValue> {
        flags.iter().map(|(n, b)| ((*n).to_owned(), AttrValue::Bool(*b))).collect()
    }

    fn softhsm() -> Side {
        let mech = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_AES_KEY_GEN"];
        Side { oaep: vec![OaepHash::Sha1], ..Side::pkcs11("softhsm", "softhsm", mech.map(String::from)) }
    }

    fn kryoptic() -> Side {
        let mech = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_KWP", "CKM_AES_KEY_GEN"];
        Side::pkcs11("kryoptic", "kryoptic", mech.map(String::from))
    }

    fn plan_of(ty: &ObjectCfg, flags: &[(&str, bool)], from: &Side, to: &To, allow: Allow) -> Plan {
        let policy = policy(flags);
        let immutables = Immutables::default();
        plan(&Material { object: "k", ty, policy: &policy, immutables: &immutables }, from, to, allow)
    }

    #[test]
    fn method_names_are_pinned_and_round_trip() {
        let names: Vec<String> = Method::BUILTIN.iter().map(Method::name).collect();
        assert_eq!(
            names,
            [
                "public",
                "rsa-oaep-sha256+aes-kwp",
                "rsa-oaep-sha1+aes-kwp",
                "rsa-oaep-sha256",
                "rsa-oaep-sha1",
                "host-pkcs8",
                "host-raw",
                "tpm2-ptool",
                "piv-import",
                "tpm-duplicate",
                "pkcs8-pbes2",
                "pkcs12",
            ]
        );
        for m in &Method::BUILTIN {
            assert_eq!(Method::from_name(&m.name()).as_ref(), Some(m));
        }
        let vendor = Method::Vendor { provider: "luna".into(), name: "clone".into() };
        assert_eq!(Method::from_name("vendor:luna/clone"), Some(vendor));
        assert_eq!(Method::from_name("vendor:luna"), None);
        assert_eq!(Method::from_name("rsa-aes"), None);
        let levels: Vec<&str> =
            [Exposure::Public, Exposure::Enforced, Exposure::Sealed, Exposure::Host, Exposure::File]
                .map(Exposure::name)
                .to_vec();
        assert_eq!(levels, ["public", "enforced", "sealed", "host", "file"]);
    }

    /// Between the software references, the composed method with the strongest common OAEP
    /// hash: SHA-1 with `SoftHSM` (it implements no other), SHA-256 between kryoptic tokens.
    #[test]
    fn sealed_between_software_references() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!(
            (p.method, p.exposure, p.ready),
            (Some(Method::RsaOaepAesKwp(OaepHash::Sha1)), Some(Exposure::Sealed), true)
        );
        let p = plan_of(&p256(), &ext, &kryoptic(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!(p.method, Some(Method::RsaOaepAesKwp(OaepHash::Sha256)));
    }

    #[test]
    fn exportability_is_fixed_at_creation() {
        for flags in [&[("CKA_EXTRACTABLE", false)][..], &[]] {
            let p = plan_of(&p256(), flags, &softhsm(), &To::Token(&kryoptic()), Allow::default());
            assert!(!p.ready && p.method.is_none(), "{p:?}");
            assert!(p.reasons[0].contains("not extractable"), "{p:?}");
        }
        let policy = policy(&[("CKA_EXTRACTABLE", true)]);
        let immutables = Immutables { never_extractable: Some(true), ..Immutables::default() };
        let ty = p256();
        let p = plan(
            &Material { object: "k", ty: &ty, policy: &policy, immutables: &immutables },
            &softhsm(),
            &To::Token(&kryoptic()),
            Allow::default(),
        );
        assert!(!p.ready && p.reasons[0].contains("not extractable"));
    }

    #[test]
    fn public_objects_move_as_they_are() {
        let cert = obj(ObjectClass::Certificate, None);
        let p = plan_of(&cert, &[], &softhsm(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!((p.method, p.exposure, p.ready), (Some(Method::Public), Some(Exposure::Public), true));
        // A PIV-like target takes certificates only.
        let piv = Side { public_import: vec![Accept::class(ObjectClass::Certificate)], ..kryoptic() };
        let data = obj(ObjectClass::Data, None);
        assert!(!plan_of(&data, &[], &softhsm(), &To::Token(&piv), Allow::default()).ready);
    }

    /// Through p11-kit (no AES key wrap): a small secret key goes directly under OAEP; a private
    /// key has no sealed path, and the host path needs AES key wrap on the source too.
    #[test]
    fn without_aes_key_wrap_only_small_secrets_are_sealed() {
        let p11kit = Side::pkcs11("p11kit", "p11-kit", ["CKM_RSA_PKCS_OAEP".to_owned()]);
        let mut aes = obj(ObjectClass::SecretKey, Some(KeyType::Aes));
        aes.value_len = Some(32);
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&aes, &ext, &p11kit, &To::Token(&kryoptic()), Allow::default());
        assert_eq!(p.method, Some(Method::RsaOaep(OaepHash::Sha256)));
        let p = plan_of(
            &p256(),
            &ext,
            &p11kit,
            &To::Token(&kryoptic()),
            Allow { host_plaintext: true, ..Allow::default() },
        );
        assert!(!p.ready && p.method.is_none(), "{p:?}");
        assert!(p.reasons.iter().any(|r| r.contains("RFC 5649")), "{p:?}");
    }

    /// A target that imports only plaintext: the host path, named even without the flag, and
    /// refused for a type it cannot take.
    #[test]
    fn host_paths_need_the_flag_and_a_type_the_target_takes() {
        let piv = Side {
            exports: false,
            unwraps: false,
            plaintext_import: Some(PlaintextImport::PivImport(vec![Accept {
                curves: vec!["secp256r1", "secp384r1"],
                ..Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec])
            }])),
            ..Side::pkcs11("yubikey", "ykcs11", Vec::new())
        };
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&piv), Allow::default());
        assert_eq!((p.method.clone(), p.exposure, p.ready), (Some(Method::PivImport), Some(Exposure::Host), false));
        assert!(p.reasons[0].contains("--allow-host-plaintext"));
        assert!(p.notes.iter().any(|n| n.contains("never attested")));
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        assert!(plan_of(&p256(), &ext, &softhsm(), &To::Token(&piv), allowed).ready);
        let mut k1 = p256();
        k1.curve = Some("secp256k1".into());
        let p = plan_of(&k1, &ext, &softhsm(), &To::Token(&piv), allowed);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("cannot import")), "{p:?}");
        // And such a token never exports.
        let p = plan_of(&p256(), &ext, &piv, &To::Token(&kryoptic()), allowed);
        assert!(p.reasons[0].contains("never lets a key leave"), "{p:?}");
    }

    #[test]
    fn wrap_with_trusted_needs_a_trusted_transport_and_never_goes_through_the_host() {
        let flags = [("CKA_EXTRACTABLE", true), ("CKA_WRAP_WITH_TRUSTED", true)];
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        let p = plan_of(&p256(), &flags, &softhsm(), &To::Token(&kryoptic()), allowed);
        assert!(!p.ready && p.method.is_none(), "{p:?}");
        assert!(p.reasons.iter().any(|r| r.contains("transport --trusted")), "{p:?}");
        let trusted = Allow { trusted_transport: true, ..allowed };
        let p = plan_of(&p256(), &flags, &softhsm(), &To::Token(&kryoptic()), trusted);
        assert_eq!((p.exposure, p.ready), (Some(Exposure::Enforced), true));
        assert!(!plan_of(&p256(), &flags, &softhsm(), &To::File(FileFormat::Pkcs8), trusted).ready);
    }

    #[test]
    fn files_carry_private_keys_behind_the_flag() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs12), Allow::default());
        assert_eq!((p.method, p.exposure, p.ready), (Some(Method::Pkcs12), Some(Exposure::File), false));
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        assert!(plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs8), allowed).ready);
    }

    /// A transport file round-trips, and one edited to name another key's identity is refused.
    #[test]
    fn transport_files_check_their_identity() {
        // Any RSA public key will do: an all-0xc5 2048-bit modulus.
        let n = [0xc5u8; 256];
        let spki = crate::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        let t = Transport::new("kryoptic", "kryoptic", "import-kek", &spki, &["CKM_RSA_PKCS_OAEP".into()]).unwrap();
        let text = toml::to_string(&t).unwrap();
        let path = std::path::Path::new("t.toml");
        assert_eq!(Transport::parse(&text, path).unwrap(), t);
        let other = text.replace(&t.rfc7093m4, &crate::id::sri(b"another key"));
        assert!(Transport::parse(&other, path).unwrap_err().to_string().contains("is not the identity"));
        let old = text.replace("version = 1", "version = 2");
        assert_eq!(Transport::parse(&old, path).unwrap_err().exit_code(), 17);
    }

    /// A provider method competes at its declared level, is noted as declared, and is used
    /// only toward the targets it names.
    #[test]
    fn vendor_methods_compete_at_their_declared_level() {
        let luna = |targets: Vec<String>| Side {
            vendor: vec![VendorMethod {
                provider: "luna".into(),
                name: "clone".into(),
                exposure: Exposure::Enforced,
                objects: vec![Accept::class(ObjectClass::PrivateKey)],
                targets,
            }],
            ..Side::pkcs11("hsm-a", "luna", Vec::new())
        };
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &luna(vec![]), &To::Token(&kryoptic()), Allow::default());
        assert_eq!(p.method, Some(Method::Vendor { provider: "luna".into(), name: "clone".into() }));
        assert_eq!(p.exposure, Some(Exposure::Enforced));
        assert!(p.notes.iter().any(|n| n.contains("declares the enforced level")), "{p:?}");
        let p = plan_of(&p256(), &ext, &luna(vec!["luna".into()]), &To::Token(&kryoptic()), Allow::default());
        assert!(!p.ready, "not toward a kryoptic target: {p:?}");
    }
}
