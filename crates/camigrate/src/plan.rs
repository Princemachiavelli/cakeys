//! Export and import planning (MIGRATE.md): which method can move an object from one token to
//! another, at which exposure, and why not when it cannot. Pure: the facts come from the lock
//! (the object's type, the source realisation's policy) and from each side's capabilities (a
//! [`Side`], built by the token's provider), so `--dry-run` and the real run share this one
//! decision (MIGRATE.md D9). The names it decides between — methods and exposure levels — are
//! the lock's, in `cakeys_core::migrate`.

use cakeys_core::config::{AttrValue, Immutables, ObjectCfg};
use cakeys_core::migrate::{Exposure, Method, PlaintextImport, Side};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::ObjectClass;
use serde::Serialize;
use std::collections::BTreeMap;

/// A passphrase-protected file format for targets cakeys cannot reach (`file` exposure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// PKCS#8 `EncryptedPrivateKeyInfo` (PBES2).
    Pkcs8,
    /// PKCS#12, the key with its certificate.
    Pkcs12,
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
    if m.ty.class == ObjectClass::SecretKey && !dst.secret_unwraps {
        blocked.push(format!(
            "{} ({}) unwraps a secret key without its length (CKA_VALUE_LEN), so its type cannot be checked \
             there",
            dst.token, dst.provider
        ));
        return;
    }
    let exposure = if trusted_only {
        if !from.trusted_wrap {
            blocked.push(format!(
                "CKA_WRAP_WITH_TRUSTED: {} ({}) cannot wrap under a transport key it trusts (its profile's \
                 trusted-wrap = false), so the key never leaves it",
                from.token, from.provider
            ));
            return;
        }
        if !allow.trusted_transport {
            blocked.push(format!(
                "CKA_WRAP_WITH_TRUSTED: {} holds no trusted copy of the transport key; its SO makes one with \
                 `camigrate transport <spec> --token <target> --trusted {}`",
                from.token, from.token
            ));
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
    // Enforced, the transport key is the only trusted key: CKM_RSA_AES_KEY_WRAP does both wraps
    // under it (its output is the composed method's, so the target unwraps it the same way).
    let composed = if trusted_only {
        cfg!(feature = "kwp") && from.has("CKM_RSA_AES_KEY_WRAP") && dst.kwp()
    } else {
        from.kwp() && dst.kwp() && from.has("CKM_AES_KEY_GEN")
    };
    if composed {
        candidates.push((Method::RsaOaepAesKwp(hash), exposure, vec![]));
    } else if m.ty.class == ObjectClass::SecretKey && m.ty.value_len.is_some_and(|n| n <= OAEP_DIRECT_MAX) {
        candidates.push((Method::RsaOaep(hash), exposure, vec![]));
    } else {
        blocked.push(if trusted_only {
            format!(
                "CKA_WRAP_WITH_TRUSTED: {} offers no CKM_RSA_AES_KEY_WRAP (or {} no RFC 5649 key wrap) to carry a {} \
                 under the trusted transport key alone",
                from.token,
                dst.token,
                describe(m.ty)
            )
        } else {
            format!(
                "{} and {} share no RFC 5649 key wrap (CKM_AES_KEY_WRAP_KWP or _PAD) to carry a {}",
                from.token,
                dst.token,
                describe(m.ty)
            )
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::migrate::{Accept, VendorMethod};
    use cakeys_core::types::KeyType;

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
        let mech = [
            "CKM_RSA_PKCS_OAEP",
            "CKM_AES_KEY_WRAP",
            "CKM_AES_KEY_WRAP_PAD",
            "CKM_AES_KEY_GEN",
            "CKM_RSA_AES_KEY_WRAP",
        ];
        Side { oaep: vec![OaepHash::Sha1], ..Side::pkcs11("softhsm", "softhsm", mech.map(String::from)) }
    }

    fn kryoptic() -> Side {
        let mech = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_KWP", "CKM_AES_KEY_GEN"];
        Side { trusted_wrap: false, ..Side::pkcs11("kryoptic", "kryoptic", mech.map(String::from)) }
    }

    fn plan_of(ty: &ObjectCfg, flags: &[(&str, bool)], from: &Side, to: &To, allow: Allow) -> Plan {
        let policy = policy(flags);
        let immutables = Immutables::default();
        plan(&Material { object: "k", ty, policy: &policy, immutables: &immutables }, from, to, allow)
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

    /// `enforced` (MIGRATE.md D2): a source that can trust a transport key and holds a trusted
    /// copy of it, `CKM_RSA_AES_KEY_WRAP` for a key OAEP cannot carry alone (only the patched
    /// cryptoki names it: the `kwp` feature), and never a host path or a file.
    #[test]
    fn wrap_with_trusted_needs_a_trusted_transport_and_never_goes_through_the_host() {
        let flags = [("CKA_EXTRACTABLE", true), ("CKA_WRAP_WITH_TRUSTED", true)];
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        let p = plan_of(&p256(), &flags, &softhsm(), &To::Token(&kryoptic()), allowed);
        assert!(!p.ready && p.method.is_none(), "{p:?}");
        assert!(p.reasons.iter().any(|r| r.contains("--trusted softhsm")), "{p:?}");
        let trusted = Allow { trusted_transport: true, ..allowed };
        let p = plan_of(&p256(), &flags, &softhsm(), &To::Token(&kryoptic()), trusted);
        assert_eq!(p.ready, cfg!(feature = "kwp"), "{p:?}");
        if p.ready {
            assert_eq!(p.exposure, Some(Exposure::Enforced));
        } else {
            assert!(p.reasons[0].contains("CKM_RSA_AES_KEY_WRAP"), "{p:?}");
        }
        let mut aes = obj(ObjectClass::SecretKey, Some(KeyType::Aes));
        aes.value_len = Some(32);
        let p = plan_of(&aes, &flags, &softhsm(), &To::Token(&kryoptic()), trusted);
        // An AES key fits under OAEP alone: CKM_RSA_AES_KEY_WRAP where this build names it, else direct.
        let method =
            if cfg!(feature = "kwp") { Method::RsaOaepAesKwp(OaepHash::Sha1) } else { Method::RsaOaep(OaepHash::Sha1) };
        assert_eq!((p.method, p.exposure, p.ready), (Some(method), Some(Exposure::Enforced), true));
        assert!(!plan_of(&p256(), &flags, &softhsm(), &To::File(FileFormat::Pkcs8), trusted).ready);
        // A source that cannot trust an RSA key (kryoptic): never, whatever is trusted.
        let p = plan_of(&p256(), &flags, &kryoptic(), &To::Token(&softhsm()), trusted);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("trusted-wrap = false")), "{p:?}");
    }

    #[test]
    fn files_carry_private_keys_behind_the_flag() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs12), Allow::default());
        assert_eq!((p.method, p.exposure, p.ready), (Some(Method::Pkcs12), Some(Exposure::File), false));
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        assert!(plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs8), allowed).ready);
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
