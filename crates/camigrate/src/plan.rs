//! Export and import planning (docs/CAMIGRATE.md): which method can move an object from one token to
//! another, at which exposure, and why not when it cannot. Pure: the facts come from the lock
//! (the object's type, the source realisation's policy) and from each side's capabilities (a
//! [`Side`], built by the token's provider), so `--dry-run` and the real run share this one
//! decision (docs/CAMIGRATE.md D9). The names it decides between — methods and exposure levels — are
//! the lock's, in `cakeys_core::migrate`.

use cakeys_core::config::{AttrValue, Immutables, ObjectCfg};
use cakeys_core::migrate::{Exposure, Method, PlaintextImport, ProbedWays, Side};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::ObjectClass;
use serde::Serialize;
use std::collections::BTreeMap;

/// A passphrase-protected file format for targets cakeys cannot reach (`file` exposure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileFormat {
    /// PKCS#8 `EncryptedPrivateKeyInfo` (PBES2).
    Pkcs8,
    /// PKCS#12, the key with its certificate.
    Pkcs12,
}

/// Where the material goes.
#[derive(Debug, Clone)]
pub(crate) enum To<'a> {
    Token(&'a Side),
    File(FileFormat),
}

/// What the planner knows about the object: its type (from the lock) and the source
/// realisation's recorded policy and immutables.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Material<'a> {
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
pub(crate) struct Allow {
    /// `--allow-host-plaintext`: the `host` and `file` paths.
    pub host_plaintext: bool,
    /// The transport key is marked `CKA_TRUSTED` on the source (phase 3b).
    pub trusted_transport: bool,
}

/// The decision for one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Plan {
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
pub(crate) fn plan(m: &Material, from: &Side, to: &To, allow: Allow) -> Plan {
    let ty = m.ty;
    // A private data object's value is a secret, and the public method would write it into a
    // bundle and recreate it under whatever CKA_PRIVATE the target defaults to (docs/OPEN.md).
    if ty.class == ObjectClass::Data && m.flag("CKA_PRIVATE") == Some(true) {
        return Plan::impossible(
            m,
            vec![
                "a private data object (CKA_PRIVATE = true): its value is a secret, and camigrate moves \
                  data objects only as public ones"
                    .into(),
            ],
        );
    }
    if is_public(ty) {
        return public(m, to);
    }
    if let Some(why) = stays(from, ty) {
        return Plan::impossible(m, vec![why]);
    }
    if m.flag("CKA_EXTRACTABLE") != Some(true) || m.immutables.never_extractable == Some(true) {
        return Plan::impossible(
            m,
            vec!["not extractable: exportability is fixed when a key is created (CKA_EXTRACTABLE = false; docs/CAMIGRATE.md D1)".into()],
        );
    }
    let trusted_only = m.flag("CKA_WRAP_WITH_TRUSTED") == Some(true);
    let mut ways = Ways::default();
    match to {
        // Before anything is offered: a target that takes the type in by no import takes it by
        // no vendor method either.
        To::Token(dst) if dst.refuses.iter().any(|a| a.covers(ty)) => ways.block(format!(
            "{} ({}) takes in no {} by any import (its profile's migration.refuses)",
            dst.token,
            dst.provider,
            describe(ty)
        )),
        To::Token(dst) => {
            // Provider methods compete at their declared level (D10).
            for v in &from.vendor {
                if v.objects.iter().any(|a| a.covers(ty)) && (v.targets.is_empty() || v.targets.contains(&dst.provider))
                {
                    let method = Method::Vendor { provider: v.provider.clone(), name: v.name.clone() };
                    let note =
                        format!("{} declares the {} level; cakeys records it, it cannot check it", method, v.exposure);
                    ways.offer_noted(method, v.exposure, note);
                }
            }
            sealed(m, from, dst, trusted_only, allow, &mut ways);
            if trusted_only {
                ways.block(
                    "CKA_WRAP_WITH_TRUSTED: only a key the source's SO marked trusted may wrap it, so no host path"
                        .into(),
                );
            } else {
                host(m, from, dst, &mut ways);
            }
        }
        To::File(format) => {
            if trusted_only {
                ways.block("CKA_WRAP_WITH_TRUSTED: it cannot be written to a file".into());
            } else if !host_extractable(from, ty) {
                ways.block(format!("{} offers no RFC 5649 key wrap to bring it to the host", from.token));
            } else {
                match format {
                    FileFormat::Pkcs8 if ty.class == ObjectClass::PrivateKey => {
                        ways.offer(Method::Pkcs8Pbes2, Exposure::File);
                    }
                    FileFormat::Pkcs12 if ty.class == ObjectClass::PrivateKey => {
                        ways.offer(Method::Pkcs12, Exposure::File);
                    }
                    _ => ways.block("PKCS#8 and PKCS#12 files carry private keys".into()),
                }
            }
        }
    }
    let Ways { mut candidates, blocked } = ways;
    candidates.sort_by_key(|c| c.exposure);
    let Some(Candidate { method, exposure, notes }) = candidates.into_iter().next() else {
        return Plan::impossible(m, blocked);
    };
    let mut plan = Plan::ready(m, method, exposure, notes);
    if matches!(exposure, Exposure::Host | Exposure::File) {
        // Why it could not stay sealed: a profile or a mechanism may be the fix, not the flag.
        plan.notes.extend(blocked.into_iter().map(|why| format!("not sealed: {why}")));
        if !allow.host_plaintext {
            plan.ready = false;
            plan.reasons.push(format!("the {exposure} path needs --allow-host-plaintext (docs/CAMIGRATE.md D2)"));
        }
    }
    if let To::Token(dst) = to {
        plan.notes.extend(target_notes(dst, &plan));
    }
    plan
}

/// One way an object could move, and what is said of it in the plan.
struct Candidate {
    method: Method,
    exposure: Exposure,
    notes: Vec<String>,
}

/// What the planner found for one object: the ways it could move, and why others cannot.
#[derive(Default)]
struct Ways {
    candidates: Vec<Candidate>,
    blocked: Vec<String>,
}

impl Ways {
    fn offer(&mut self, method: Method, exposure: Exposure) {
        self.candidates.push(Candidate { method, exposure, notes: vec![] });
    }

    fn offer_noted(&mut self, method: Method, exposure: Exposure, note: String) {
        self.candidates.push(Candidate { method, exposure, notes: vec![note] });
    }

    fn block(&mut self, why: String) {
        self.blocked.push(why);
    }
}

/// A public object's plan: created from its value where the target's probed `create.*` row
/// says so, else where its claims accept the class.
fn public(m: &Material, to: &To) -> Plan {
    let ty = m.ty;
    match to {
        To::Token(dst) => match ProbedWays::of(&dst.probed.create, ty) {
            Some(r) if r.yes => Plan::ready(m, Method::Public, Exposure::Public, vec![]),
            Some(_) => Plan::impossible(
                m,
                vec![format!("{} creates no {} (its create.* row says no)", dst.token, describe(ty))],
            ),
            None if dst.public_import.iter().any(|a| a.covers(ty)) => {
                Plan::ready(m, Method::Public, Exposure::Public, vec![])
            }
            None => Plan::impossible(m, vec![format!("{} accepts no {} by import", dst.token, describe(ty))]),
        },
        To::File(_) => Plan::impossible(m, vec!["files carry private keys; a public object needs no export".into()]),
    }
}

/// Why a key of type `ty` never leaves `from`, if it does not: its probed `export.*` rows decide
/// for the type they name, the module's claim for the rest.
fn stays(from: &Side, ty: &ObjectCfg) -> Option<String> {
    let leaves =
        [&from.probed.export_host, &from.probed.export_sealed].map(|rows| ProbedWays::of(rows, ty).map(|r| r.yes));
    match leaves {
        [Some(false), Some(false)] => Some(format!(
            "{} ({}) lets no {} leave the token (its export.host and export.sealed rows say no)",
            from.token,
            from.provider,
            describe(ty)
        )),
        l if l.contains(&Some(true)) => None,
        _ => (!from.exports).then(|| format!("{} ({}) never lets a key leave the token", from.token, from.provider)),
    }
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
fn sealed(m: &Material, from: &Side, dst: &Side, trusted_only: bool, allow: Allow, ways: &mut Ways) {
    match ProbedWays::of(&dst.probed.unwrap, m.ty).map(|r| r.yes) {
        Some(false) => {
            ways.block(format!(
                "{} ({}) does not unwrap a {} (its unwrap.* row says no)",
                dst.token,
                dst.provider,
                describe(m.ty)
            ));
            return;
        }
        None if !dst.unwraps => {
            ways.block(format!("{} ({}) unwraps nothing", dst.token, dst.provider));
            return;
        }
        _ => {}
    }
    if ProbedWays::of(&from.probed.export_sealed, m.ty).is_some_and(|r| !r.yes) {
        ways.block(format!(
            "{} ({}) wraps no {} toward another token (its export.sealed.* row says no)",
            from.token,
            from.provider,
            describe(m.ty)
        ));
        return;
    }
    if m.ty.class == ObjectClass::SecretKey && !dst.secret_unwraps {
        ways.block(format!(
            "{} ({}) unwraps a secret key without its length (CKA_VALUE_LEN), so its type cannot be checked \
             there",
            dst.token, dst.provider
        ));
        return;
    }
    let exposure = if trusted_only {
        if !from.trusted_wrap {
            ways.block(format!(
                "CKA_WRAP_WITH_TRUSTED: {} ({}) cannot wrap under a transport key it trusts (its profile's \
                 move.trusted-wrap row says no), so the key never leaves it",
                from.token, from.provider
            ));
            return;
        }
        if !allow.trusted_transport {
            ways.block(format!(
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
        ways.block(format!("no RSA-OAEP hash both {} and {} implement", from.token, dst.token));
        return;
    };
    // Enforced, the transport key is the only trusted key: CKM_RSA_AES_KEY_WRAP does both wraps
    // under it (its output is the composed method's, so the target unwraps it the same way). A
    // side without RFC 5649 of its own takes the same mechanism instead (`sealed`).
    let rsa_aes = |s: &Side| cfg!(feature = "kwp") && s.has("CKM_RSA_AES_KEY_WRAP");
    let unwraps_composed = dst.kwp() || rsa_aes(dst);
    let composed = if trusted_only {
        rsa_aes(from) && unwraps_composed
    } else {
        ((from.kwp() && from.has("CKM_AES_KEY_GEN")) || rsa_aes(from)) && unwraps_composed
    };
    if composed {
        ways.offer(Method::RsaOaepAesKwp(hash), exposure);
    } else if m.ty.class == ObjectClass::SecretKey && m.ty.value_len.is_some_and(|n| n <= OAEP_DIRECT_MAX) {
        ways.offer(Method::RsaOaep(hash), exposure);
    } else {
        ways.block(if trusted_only {
            format!(
                "CKA_WRAP_WITH_TRUSTED: {} offers no CKM_RSA_AES_KEY_WRAP (or {} no RFC 5649 key wrap) to carry a {} \
                 under the trusted transport key alone",
                from.token,
                dst.token,
                describe(m.ty)
            )
        } else {
            format!(
                "{} and {} share no RFC 5649 key wrap (CKM_AES_KEY_WRAP_KWP or _PAD, or CKM_RSA_AES_KEY_WRAP) to carry a {}",
                from.token,
                dst.token,
                describe(m.ty)
            )
        });
    }
}

/// The largest secret key RSA-OAEP carries directly under a 2048-bit transport key with SHA-256
/// (256 - 2 × 32 - 2 bytes); larger transport keys carry more, and none is smaller
/// (`sealed::check_transport_size`).
const OAEP_DIRECT_MAX: u64 = 190;

/// Whether the source can hand the material to the host: wrapped under a session key cakeys
/// knows, then unwrapped in memory. Every class by RFC 5649, the one wrap `Token::extract`
/// undoes; RFC 3394 alone (`CKM_AES_KEY_WRAP`) is not taken. A probed `export.host.*` row for
/// the type decides.
fn host_extractable(from: &Side, ty: &ObjectCfg) -> bool {
    ProbedWays::of(&from.probed.export_host, ty).map_or_else(|| from.kwp(), |r| r.yes)
}

/// The `host` methods into a token: a probed `import.*` row for the type decides, its `via` the
/// path; else the module's claimed path.
fn host(m: &Material, from: &Side, dst: &Side, ways: &mut Ways) {
    let ty = m.ty;
    let probed = ProbedWays::of(&dst.probed.import, ty);
    if probed.is_some_and(|r| !r.yes) {
        ways.block(format!(
            "{} ({}) does not import a {} (its import.* row says no)",
            dst.token,
            dst.provider,
            describe(ty)
        ));
        return;
    }
    if probed.is_none() && dst.plaintext_import.is_none() {
        ways.block(format!("{} ({}) imports no key material", dst.token, dst.provider));
        return;
    }
    if !host_extractable(from, ty) {
        ways.block(format!("{} offers no RFC 5649 key wrap to bring it to the host", from.token));
        return;
    }
    let create_object = || if ty.class == ObjectClass::PrivateKey { Method::HostPkcs8 } else { Method::HostRaw };
    let method = match (probed.and_then(|r| r.via.as_deref()), &dst.plaintext_import) {
        (Some("tpm2-ptool"), _) => Method::Tpm2Ptool,
        (Some("piv-import"), _) => Method::PivImport,
        (Some(_), _) | (None, Some(PlaintextImport::CreateObject)) => create_object(),
        (None, Some(PlaintextImport::Tpm2Ptool(accepts))) if accepts.iter().any(|a| a.covers(ty)) => Method::Tpm2Ptool,
        (None, Some(PlaintextImport::PivImport(accepts))) if accepts.iter().any(|a| a.covers(ty)) => Method::PivImport,
        (None, _) => {
            ways.block(format!("{} ({}) cannot import a {}", dst.token, dst.provider, describe(ty)));
            return;
        }
    };
    ways.offer(method, Exposure::Host);
}

/// What the target changes about the object, whatever moves it.
fn target_notes(dst: &Side, plan: &Plan) -> Vec<String> {
    match plan.method {
        Some(Method::PivImport) => {
            vec!["an imported PIV key is never attested; `attestation = true` is refused there".into()]
        }
        Some(Method::Tpm2Ptool) => vec![
            format!("{} can attest the key's residence, not its generation (CKA_LOCAL = false)", dst.token),
            "the key enters tpm2_ptool's own process, which cakeys cannot zeroize, through an in-memory file, never \
             a file on disk"
                .into(),
            format!(
                "tpm2_ptool takes {}'s user PIN only on its command line, where other local users can read it while it runs",
                dst.token
            ),
        ],
        Some(Method::TpmDuplicate) => {
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

    /// AWS `CloudHSM` once its profile subtracts the AES key wraps it lists but refuses \[run\]:
    /// RFC 5649 only inside `CKM_RSA_AES_KEY_WRAP`.
    fn cloudhsm() -> Side {
        let mech = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_GEN", "CKM_RSA_AES_KEY_WRAP"];
        Side::pkcs11("cloudhsm", "aws-cloudhsm", mech.map(String::from))
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
        let p = plan_of(&data, &[("CKA_PRIVATE", false)], &softhsm(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!((p.method, p.ready), (Some(Method::Public), true));
        // A private data object's value is a secret: no method, whatever is allowed.
        let everything = Allow { host_plaintext: true, trusted_transport: true };
        for to in [To::Token(&kryoptic()), To::File(FileFormat::Pkcs8)] {
            let p = plan_of(&data, &[("CKA_PRIVATE", true)], &softhsm(), &to, everything);
            assert!(!p.ready && p.method.is_none(), "{p:?}");
            assert!(p.reasons[0].contains("private data object"), "{p:?}");
        }
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

    /// `enforced` (docs/CAMIGRATE.md D2): a source that can trust a transport key and holds a trusted
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
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("move.trusted-wrap row says no")), "{p:?}");
    }

    /// A side whose RFC 5649 is only `CKM_RSA_AES_KEY_WRAP` (`CloudHSM`) takes the composed method
    /// through it, in and out: where this build names the mechanism (the `kwp` feature). Without
    /// it, a source with RFC 5649 of its own still reaches the host path, which needs its flag;
    /// one without has no way out and says why.
    #[test]
    fn rsa_aes_key_wrap_stands_in_for_rfc_5649() {
        let ext = [("CKA_EXTRACTABLE", true)];
        for (from, to) in [(softhsm(), cloudhsm()), (cloudhsm(), softhsm()), (cloudhsm(), kryoptic())] {
            let p = plan_of(&p256(), &ext, &from, &To::Token(&to), Allow::default());
            let pair = format!("{} -> {}", from.token, to.token);
            assert_eq!(p.ready, cfg!(feature = "kwp"), "{pair}: {p:?}");
            assert_eq!(matches!(p.method, Some(Method::RsaOaepAesKwp(_))), p.ready, "{pair}: {p:?}");
            if !p.ready && from.kwp() {
                assert_eq!(p.method, Some(Method::HostPkcs8), "{pair}: {p:?}");
            } else if !p.ready {
                assert!(p.reasons.iter().any(|r| r.contains("CKM_RSA_AES_KEY_WRAP")), "{pair}: {p:?}");
            }
        }
    }

    /// A target whose profile refuses a key kind (`migration.refuses`: `CloudHSM`'s Ed25519 \[run\])
    /// is blocked with that reason, whatever wrap both sides share; other keys still move.
    #[test]
    fn a_refused_key_kind_is_blocked_at_the_target() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let mut ed = obj(ObjectClass::PrivateKey, Some(KeyType::EcEdwards));
        ed.curve = Some("edwards25519".into());
        let refusing = Side {
            refuses: vec![Accept { key_types: vec![KeyType::EcEdwards], ..Accept::class(ObjectClass::PrivateKey) }],
            ..softhsm()
        };
        let p =
            plan_of(&ed, &ext, &kryoptic(), &To::Token(&refusing), Allow { host_plaintext: true, ..Allow::default() });
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("migration.refuses")), "{p:?}");
        assert!(plan_of(&p256(), &ext, &kryoptic(), &To::Token(&refusing), Allow::default()).ready);
        // As a source it still exports.
        assert!(plan_of(&ed, &ext, &refusing, &To::Token(&kryoptic()), Allow::default()).ready);
    }

    #[test]
    fn files_carry_private_keys_behind_the_flag() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let p = plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs12), Allow::default());
        assert_eq!((p.method, p.exposure, p.ready), (Some(Method::Pkcs12), Some(Exposure::File), false));
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        assert!(plan_of(&p256(), &ext, &softhsm(), &To::File(FileFormat::Pkcs8), allowed).ready);
        // A public object needs no file, and a source with no RFC 5649 key wrap cannot hand a key
        // to the host at all.
        let cert = obj(ObjectClass::Certificate, None);
        let p = plan_of(&cert, &[], &softhsm(), &To::File(FileFormat::Pkcs8), allowed);
        assert!(!p.ready && p.reasons[0].contains("a public object needs no export"), "{p:?}");
        let bare = Side::pkcs11("bare", "generic", ["CKM_RSA_PKCS_OAEP".to_owned()]);
        let p = plan_of(&p256(), &ext, &bare, &To::File(FileFormat::Pkcs8), allowed);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("offers no RFC 5649 key wrap")), "{p:?}");
    }

    /// Each fact the planner names decides on its own (the mutation report's gaps): a secret
    /// key needs a target that reports its length; the composed method needs RFC 5649 on both
    /// sides and a KEK the source can make; without it only a small secret goes directly; the
    /// host path creates a private key from PKCS#8 and a secret from its value, and a tool
    /// import takes only what it lists; a file carries private keys only. Refusals name the
    /// object's type.
    #[test]
    fn each_fact_the_planner_names_decides() {
        let ext = [("CKA_EXTRACTABLE", true)];
        let side = |name: &str, mech: &[&str]| Side::pkcs11(name, name, mech.iter().map(|m| (*m).to_owned()));
        let full = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP_KWP", "CKM_AES_KEY_GEN"];
        let both = side("a", &full);
        let mut aes = obj(ObjectClass::SecretKey, Some(KeyType::Aes));
        aes.value_len = Some(32);
        let mut big = obj(ObjectClass::SecretKey, Some(KeyType::GenericSecret));
        big.value_len = Some(256);
        let sealed_to =
            |ty: &ObjectCfg, from: &Side, to: &Side| plan_of(ty, &ext, from, &To::Token(to), Allow::default());
        let composed = Some(Method::RsaOaepAesKwp(OaepHash::Sha256));
        assert_eq!(sealed_to(&p256(), &both, &both).method, composed);
        // A target that reports no length for an unwrapped secret takes private keys only.
        let lengthless = Side { secret_unwraps: false, plaintext_import: None, ..both.clone() };
        assert_eq!(sealed_to(&p256(), &both, &lengthless).method, composed);
        let p = sealed_to(&aes, &both, &lengthless);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("without its length")), "{p:?}");
        // The composed method: RFC 5649 on the source, on the target, and a KEK to generate.
        let no_import = |s: Side| Side { plaintext_import: None, ..s };
        for (from, to) in [
            (side("src", &["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_GEN"]), both.clone()),
            (both.clone(), side("dst", &["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_GEN"])),
            (side("src", &["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP_KWP"]), both.clone()),
        ] {
            let to = no_import(to);
            let p = sealed_to(&p256(), &from, &to);
            assert!(!p.ready && p.reasons.iter().any(|r| r.contains("share no RFC 5649")), "{p:?}");
            assert!(p.reasons.iter().any(|r| r.contains("CKO_PRIVATE_KEY CKK_EC secp256r1")), "{p:?}");
            // Directly under OAEP: a small secret, never a large one.
            assert_eq!(sealed_to(&aes, &from, &to).method, Some(Method::RsaOaep(OaepHash::Sha256)));
            let p = sealed_to(&big, &from, &to);
            assert!(!p.ready && p.reasons.iter().any(|r| r.contains("CKO_SECRET_KEY CKK_GENERIC_SECRET")), "{p:?}");
        }
        // The host path, into a target that unwraps nothing.
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        let host_to = |ty: &ObjectCfg, to: &Side| plan_of(ty, &ext, &both, &To::Token(to), allowed);
        let creates = Side { unwraps: false, ..both.clone() };
        assert_eq!(host_to(&p256(), &creates).method, Some(Method::HostPkcs8));
        assert_eq!(host_to(&aes, &creates).method, Some(Method::HostRaw));
        let tool = |accepts: Vec<Accept>| Side {
            unwraps: false,
            plaintext_import: Some(PlaintextImport::Tpm2Ptool(accepts)),
            ..both.clone()
        };
        let takes_ec = tool(vec![Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec])]);
        assert_eq!(host_to(&p256(), &takes_ec).method, Some(Method::Tpm2Ptool));
        let p = host_to(&aes, &takes_ec);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("cannot import a CKO_SECRET_KEY CKK_AES")), "{p:?}");
        // A file carries private keys, in either format.
        for format in [FileFormat::Pkcs8, FileFormat::Pkcs12] {
            let p = plan_of(&aes, &ext, &both, &To::File(format), allowed);
            assert!(!p.ready && p.reasons.iter().any(|r| r.contains("carry private keys")), "{p:?}");
        }
    }

    /// `enforced` needs `CKM_RSA_AES_KEY_WRAP` on the source and RFC 5649 on the target, each on
    /// its own: without either a private key cannot leave under the trusted transport key.
    #[test]
    fn the_enforced_composed_method_needs_both_sides() {
        let flags = [("CKA_EXTRACTABLE", true), ("CKA_WRAP_WITH_TRUSTED", true)];
        let side = |mech: &[&str]| Side::pkcs11("t", "t", mech.iter().map(|m| (*m).to_owned()));
        let trusted = Allow { trusted_transport: true, ..Allow::default() };
        let source = ["CKM_RSA_PKCS_OAEP", "CKM_RSA_AES_KEY_WRAP"];
        let target = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_WRAP_KWP"];
        for (from, to) in [(side(&source), side(&["CKM_RSA_PKCS_OAEP"])), (side(&["CKM_RSA_PKCS_OAEP"]), side(&target))]
        {
            let p = plan_of(&p256(), &flags, &from, &To::Token(&to), trusted);
            assert!(!p.ready && p.reasons.iter().any(|r| r.contains("CKM_RSA_AES_KEY_WRAP")), "{p:?}");
        }
        let p = plan_of(&p256(), &flags, &side(&source), &To::Token(&side(&target)), trusted);
        assert_eq!(p.ready, cfg!(feature = "kwp"), "{p:?}");
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
        // A target whose migration.refuses covers the key takes it by no vendor method either.
        let refusing = Side { refuses: vec![Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec])], ..kryoptic() };
        let p = plan_of(&p256(), &ext, &luna(vec![]), &To::Token(&refusing), Allow::default());
        assert!(!p.ready && p.method.is_none(), "{p:?}");
        assert!(p.reasons.iter().any(|r| r.contains("migration.refuses")), "{p:?}");
    }

    /// A key that goes by the host path says why no sealed way would carry it: the fix may be a
    /// profile or a mechanism rather than --allow-host-plaintext (review plan.rs F2).
    #[test]
    fn a_host_plan_says_why_it_is_not_sealed() {
        let ext = [("CKA_EXTRACTABLE", true)];
        // A target that unwraps nothing: only the host path, through its create-object import.
        let plain_only = Side {
            unwraps: false,
            plaintext_import: Some(PlaintextImport::CreateObject),
            ..Side::pkcs11("plain", "plain", ["CKM_AES_KEY_WRAP_PAD".to_owned()])
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&plain_only), Allow::default());
        assert_eq!((p.exposure, p.ready), (Some(Exposure::Host), false), "{p:?}");
        assert!(p.reasons.iter().any(|r| r.contains("--allow-host-plaintext")), "{p:?}");
        assert!(p.notes.iter().any(|n| n.starts_with("not sealed: ")), "{p:?}");
        let allowed = plan_of(
            &p256(),
            &ext,
            &softhsm(),
            &To::Token(&plain_only),
            Allow { host_plaintext: true, ..Allow::default() },
        );
        assert!(allowed.ready && allowed.notes.iter().any(|n| n.starts_with("not sealed: ")), "{allowed:?}");
    }

    /// A probed row decides for the type it covers, before the module's claims
    /// (`docs/archive/CAPROBE_MIGRATION.md`, M4), and only for that type.
    #[test]
    fn probed_rows_decide_before_the_claims_for_their_type() {
        use cakeys_core::migrate::{Probed, ProbedWays};
        let ext = [("CKA_EXTRACTABLE", true)];
        let p256_rows = |yes, via: Option<&str>| {
            vec![Probed {
                covers: Accept { curves: vec!["secp256r1"], ..Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec]) },
                yes,
                via: via.map(str::to_owned),
            }]
        };
        let host = Allow { host_plaintext: true, ..Allow::default() };
        // The target claims C_CreateObject; its import row for P-256 says no: no host path,
        // and a P-384 key, which no row covers, still takes the claim.
        let no_import = Side {
            unwraps: false,
            probed: ProbedWays { import: p256_rows(false, None), ..ProbedWays::default() },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&no_import), host);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("its import.* row says no")), "{p:?}");
        let p384 = ObjectCfg { curve: Some("secp384r1".into()), ..p256() };
        let p = plan_of(&p384, &ext, &softhsm(), &To::Token(&no_import), host);
        assert_eq!((p.method, p.ready), (Some(Method::HostPkcs8), true), "{:?}", p.reasons);
        // The target claims to unwrap nothing; its unwrap row for P-256 says yes: sealed.
        let unwraps = Side {
            unwraps: false,
            probed: ProbedWays { unwrap: p256_rows(true, Some("rsa-oaep-sha1+aes-kwp")), ..ProbedWays::default() },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&unwraps), Allow::default());
        assert_eq!((p.exposure, p.ready), (Some(Exposure::Sealed), true), "{:?}", p.reasons);
        // An import row's path is the method: a module whose claim is tpm2_ptool for nothing.
        let ptool = Side {
            unwraps: false,
            plaintext_import: Some(PlaintextImport::Tpm2Ptool(vec![])),
            probed: ProbedWays { import: p256_rows(true, Some("tpm2-ptool")), ..ProbedWays::default() },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&ptool), host);
        assert_eq!(p.method, Some(Method::Tpm2Ptool), "{:?}", p.reasons);
        // The source claims to export; both its export rows for P-256 say no: the key stays.
        let keeps = Side {
            probed: ProbedWays {
                export_host: p256_rows(false, None),
                export_sealed: p256_rows(false, None),
                ..ProbedWays::default()
            },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &keeps, &To::Token(&kryoptic()), host);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("export.host and export.sealed rows say no")), "{p:?}");
        // A public object: the create row decides over the claimed classes.
        let cert = obj(ObjectClass::Certificate, None);
        let no_certs = Side {
            probed: ProbedWays {
                create: vec![Probed { covers: Accept::class(ObjectClass::Certificate), yes: false, via: None }],
                ..ProbedWays::default()
            },
            ..softhsm()
        };
        let p = plan_of(&cert, &[], &softhsm(), &To::Token(&no_certs), host);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("its create.* row says no")), "{p:?}");
    }
}
