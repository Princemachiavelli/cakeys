//! Export and import planning (docs/CAMIGRATE.md): which method can move an object from one token
//! to another, at which exposure, and the reasons when no method can. The planning is pure. The
//! facts come from the lock (the object's type and the source realisation's policy) and from the
//! capabilities of each side (a [`Side`], built from the token's profiles by `tokens::side`).
//! Therefore, `--dry-run` and the real run share this one decision (docs/CAMIGRATE.md D9). The
//! names of the methods and of the exposure levels that it chooses between are the lock's names,
//! in `cakeys_core::migrate`.

use crate::side::{PlaintextImport, ProbedWays, Side};
use cakeys_core::KmError;
use cakeys_core::config::{AttrValue, Immutables, ObjectCfg};
use cakeys_core::known::{Known, Permission, Restriction, Why};
use cakeys_core::migrate::{Exposure, Method, OaepHash};
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::ops::Rule;
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

/// What the planner knows about the object: its type (from the lock), and the policy and the
/// immutable attributes that the source realisation records.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Material<'a> {
    pub object: &'a str,
    pub ty: &'a ObjectCfg,
    pub policy: &'a BTreeMap<String, AttrValue>,
    pub immutables: &'a Immutables,
}

impl Material<'_> {
    /// Returns the boolean attribute `name` as the source's lock recorded it, or `Unrecorded` when
    /// the lock did not record it. Before review 2026-11-24 D-7, an unrecorded attribute was read
    /// as `false`.
    fn known(&self, name: &str) -> Known<bool> {
        Known::or(
            match self.policy.get(name) {
                Some(AttrValue::Bool(b)) => Some(*b),
                _ => None,
            },
            Why::Unrecorded,
        )
    }

    /// Returns whether the restriction `r` holds. An unrecorded restriction holds.
    fn restricted(&self, r: Restriction) -> bool {
        self.known(r.attr()).restricts()
    }

    /// Returns whether the permission `p` is granted. An unrecorded permission is not granted.
    fn permitted(&self, p: Permission) -> bool {
        self.known(p.attr()).permits()
    }
}

/// What the caller allows the plan to use.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Allow {
    /// `--allow-host-plaintext`, which allows the `host` and `file` paths.
    pub host_plaintext: bool,
    /// Whether the transport key is marked `CKA_TRUSTED` on the source (phase 3b).
    pub trusted_transport: bool,
}

/// The decision for one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Plan {
    pub object: String,
    /// The method that would be used, also when a flag is missing. `None` when no method fits.
    #[serde(serialize_with = "method_name")]
    pub method: Option<Method>,
    pub exposure: Option<Exposure>,
    /// Whether the move can run as invoked.
    pub ready: bool,
    /// The reasons why the move cannot run (or what is missing), when it is not ready.
    pub reasons: Vec<String>,
    /// What changes during the move (for example, attestation or a declared vendor level).
    pub notes: Vec<String>,
    /// The names of the rules that only the run decides (`ops::Deferred`). When the plan was
    /// ready, the run may end with one of these rules, and with no other refusal
    /// (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4). The notes give the reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<&'static str>,
    /// The refusal that blocked the plan, when a rule that the write asks blocked it (for
    /// example, a placement with 17, or an occupied locator with 13). The run would end with this
    /// refusal, so the plan ends with it too ([`Refused::error`]; review 2026-11-24 D-2, D-3).
    /// `None` when the plan is ready, or when it was blocked for a reason of its own (15).
    #[serde(skip)]
    pub refused: Option<Refused>,
}

/// The refusal that blocked a plan ([`Plan::refuse`]).
#[derive(Debug, Clone)]
pub(crate) struct Refused(KmError);

/// Two refusals are equal when their exit codes, rules, checks and messages are equal.
impl PartialEq for Refused {
    fn eq(&self, other: &Refused) -> bool {
        let said = |e: &KmError| (e.exit_code(), e.rule(), e.check(), e.to_string());
        said(&self.0) == said(&other.0)
    }
}

impl Eq for Refused {}

impl Refused {
    /// Returns `text` as the error that the run ends with. The error has this refusal's exit code,
    /// rule and check, and no return value. A plan's rules refuse with 13, 14, 16 or 17. A refusal
    /// with any other code ends the run with 15.
    pub(crate) fn error(self, text: String) -> KmError {
        let Refused(e) = self;
        if matches!(e.exit_code(), 13 | 14 | 16 | 17) {
            return e.with_text(text).with_rv(None);
        }
        let unsupported = KmError::Unsupported(text.into());
        let unsupported = match e.rule() {
            Some(rule) => unsupported.with_rule(rule),
            None => unsupported,
        };
        match e.check() {
            Some(check) => unsupported.with_check(check),
            None => unsupported,
        }
    }
}

#[expect(clippy::ref_option, reason = "serde's serialize_with hands the field by reference")]
fn method_name<S: serde::Serializer>(m: &Option<Method>, s: S) -> Result<S::Ok, S::Error> {
    match m {
        Some(m) => s.serialize_str(&m.name()),
        None => s.serialize_none(),
    }
}

impl Plan {
    /// Blocks the plan, because the run would refuse it for the reason `why`. Before review
    /// 2026-11-23 C-23, each rule cleared `ready` and added its reason itself.
    pub(crate) fn block(&mut self, why: impl Into<String>) {
        self.ready = false;
        self.reasons.push(why.into());
    }

    /// Blocks the plan ([`Self::block`]) for the refusal `e` of a rule that the write asks. If the
    /// plan was ready, it then ends with `e`'s exit code and rule ([`Self::refused`]).
    pub(crate) fn refuse(&mut self, e: KmError) {
        if self.ready {
            self.refused = Some(Refused(e.clone()));
        }
        self.block(crate::trust::reason(e));
    }

    /// Returns `text` as the error that a run ends with for this blocked plan. It is the error of
    /// the plan's refusal ([`Refused::error`]), or `Unsupported` (15) when the plan was blocked for
    /// a reason of its own.
    pub(crate) fn refusal(&self, text: String) -> KmError {
        match self.refused.clone() {
            Some(r) => r.error(text),
            None => KmError::Unsupported(text.into()),
        }
    }

    /// Returns the plan of `object` when the run could not plan it, with `why` as the reason. The
    /// plan has no method, and it is blocked. A run that fails before its plans exist still shows
    /// one plan for each object. Before review 2026-11-24 L4b-1, such a dry run printed no plan.
    pub(crate) fn unplanned(object: &str, why: String) -> Plan {
        Plan {
            object: object.into(),
            method: None,
            exposure: None,
            ready: false,
            reasons: vec![why],
            notes: vec![],
            deferred: vec![],
            refused: None,
        }
    }

    /// Blocks the plan as [`Self::block`] does, but puts `why` first among the reasons. A reason
    /// that keeps the object on its token matters more than the reasons about how it would move.
    pub(crate) fn block_first(&mut self, why: impl Into<String>) {
        self.ready = false;
        self.reasons.insert(0, why.into());
    }

    fn ready(m: &Material, method: Method, exposure: Exposure) -> Plan {
        Plan {
            object: m.object.into(),
            method: Some(method),
            exposure: Some(exposure),
            ready: true,
            reasons: vec![],
            notes: vec![],
            deferred: vec![],
            refused: None,
        }
    }

    fn impossible(m: &Material, reasons: Vec<String>) -> Plan {
        Plan {
            object: m.object.into(),
            method: None,
            exposure: None,
            ready: false,
            reasons,
            notes: vec![],
            deferred: vec![],
            refused: None,
        }
    }
}

/// Decides how `m` moves from `from` to `to`. The candidate methods are sorted by exposure, and
/// the method with the strongest exposure is taken. A method that needs a flag that the caller did
/// not give is still named, with `ready = false` and the flag in `reasons`.
#[must_use]
pub(crate) fn plan(m: &Material, from: &Side, to: &To, allow: Allow) -> Plan {
    let ty = m.ty;
    // A private data object's value is a secret. The public method would write the value into a
    // bundle and recreate the object with whatever `CKA_PRIVATE` value the target uses by default
    // (docs/OPEN.md). A data object that the lock does not record as public is treated as
    // private (D-7).
    if ty.class == ObjectClass::Data && m.restricted(Restriction::Private) {
        return Plan::impossible(
            m,
            vec![format!(
                "a private data object (CKA_PRIVATE = {}): its value is a secret, and camigrate moves data objects \
                 only as public ones",
                m.known(Restriction::Private.attr())
            )],
        );
    }
    if is_public(ty) {
        return public(m, to);
    }
    if let Some(why) = stays(from, ty) {
        return Plan::impossible(m, vec![why]);
    }
    // The lock must record `CKA_EXTRACTABLE = true`. A key whose `CKA_NEVER_EXTRACTABLE` is
    // recorded as true was non-extractable when it was created, so it is refused even when it
    // reports `CKA_EXTRACTABLE = true`. An unrecorded `CKA_NEVER_EXTRACTABLE` decides nothing more.
    if !m.permitted(Permission::Extractable) || m.immutables.never_extractable == Some(true) {
        return Plan::impossible(
            m,
            vec!["not extractable: exportability is fixed when a key is created (CKA_EXTRACTABLE = false; docs/CAMIGRATE.md D1)".into()],
        );
    }
    // An unrecorded `CKA_WRAP_WITH_TRUSTED` counts as true, so that only a trusted transport key
    // may wrap the key (D-7).
    let trusted_only = m.restricted(Restriction::WrapWithTrusted);
    let mut ways = Ways::default();
    match to {
        // Before any method is offered, check whether the target refuses the type for every
        // import.
        To::Token(dst) if dst.refuses.iter().any(|a| a.covers(ty)) => ways.block(format!(
            "{} ({}) takes in no {} by any import (its profile's migration.refuses)",
            dst.token,
            dst.provider,
            describe(ty)
        )),
        // No profile or provider declares a method of its own (D10, `Method::Vendor`) yet, so no
        // vendor method is offered here (review 2026-11-23 C-17).
        To::Token(dst) => {
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
    let Some(Candidate { method, exposure, deferred }) = candidates.into_iter().next() else {
        return Plan::impossible(m, blocked);
    };
    let mut plan = Plan::ready(m, method, exposure);
    plan.deferred.extend(deferred);
    if matches!(exposure, Exposure::Host | Exposure::File) {
        // Add the reasons why the move could not stay sealed, because the fix may be a profile or
        // a mechanism instead of the flag.
        plan.notes.extend(blocked.into_iter().map(|why| format!("not sealed: {why}")));
        if !allow.host_plaintext {
            plan.block(format!("the {exposure} path needs --allow-host-plaintext (docs/CAMIGRATE.md D2)"));
        }
    }
    if let To::Token(dst) = to {
        plan.notes.extend(target_notes(dst, &plan));
    }
    plan
}

/// One way in which an object could move, and what the plan says about it.
struct Candidate {
    method: Method,
    exposure: Exposure,
    /// A rule that the plan cannot decide and that the run decides. It is set when the way depends
    /// on a probed yes that only the module reported (`Rule::Capability`).
    deferred: Option<&'static str>,
}

/// What the planner found for one object: the ways in which it could move, and the reasons why
/// the other ways cannot move it.
#[derive(Default)]
struct Ways {
    candidates: Vec<Candidate>,
    blocked: Vec<String>,
}

impl Ways {
    fn offer(&mut self, method: Method, exposure: Exposure) {
        self.candidates.push(Candidate { method, exposure, deferred: None });
    }

    /// Offers a way as [`Self::offer`] does. When the way depends on a probed yes that only the
    /// module reported (`unverified`), the plan defers the capability to the run.
    fn offer_unless(&mut self, method: Method, exposure: Exposure, unverified: bool) {
        let deferred = unverified.then(|| Rule::Capability.name());
        self.candidates.push(Candidate { method, exposure, deferred });
    }

    fn block(&mut self, why: String) {
        self.blocked.push(why);
    }
}

/// Returns a public object's plan. The object is created from its value when the target's probed
/// `create.*` row says yes, or, when no row covers it, when the target's claims accept the class.
fn public(m: &Material, to: &To) -> Plan {
    let ty = m.ty;
    match to {
        To::Token(dst) => match ProbedWays::of(&dst.probed.create, ty) {
            Some(r) if r.yes => Plan::ready(m, Method::Public, Exposure::Public),
            Some(r) => {
                Plan::impossible(m, vec![format!("{} creates no {} ({})", dst.token, describe(ty), r.said("create.*"))])
            }
            None if dst.public_import.iter().any(|a| a.covers(ty)) => Plan::ready(m, Method::Public, Exposure::Public),
            None => Plan::impossible(m, vec![format!("{} accepts no {} by import", dst.token, describe(ty))]),
        },
        To::File(_) => Plan::impossible(m, vec!["files carry private keys; a public object needs no export".into()]),
    }
}

/// Returns the reason why a key of type `ty` never leaves `from`, or `None` when it can leave. The
/// probed `export.*` rows decide for the types that they cover, and the module's claim decides for
/// the other types.
fn stays(from: &Side, ty: &ObjectCfg) -> Option<String> {
    let rows = [&from.probed.export_host, &from.probed.export_sealed].map(|rows| ProbedWays::of(rows, ty));
    let leaves = rows.map(|r| r.map(|r| r.yes));
    match (leaves, rows) {
        ([Some(false), Some(false)], [Some(host), Some(sealed)]) => Some(format!(
            "{} ({}) lets no {} leave the token ({}; {})",
            from.token,
            from.provider,
            describe(ty),
            host.said("export.host.*"),
            sealed.said("export.sealed.*")
        )),
        (l, _) if l.contains(&Some(true)) => None,
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

/// Offers the `sealed` (or `enforced`) methods between two PKCS#11 modules, or records why they
/// cannot move the object.
fn sealed(m: &Material, from: &Side, dst: &Side, trusted_only: bool, allow: Allow, ways: &mut Ways) {
    // A yes that only the module reported (`by = "unverified"`: its own round trip, with no blob
    // decoded on the host) is accepted, and the capability is deferred to the run (review
    // 2026-11-24 E-3).
    let unverified = [ProbedWays::of(&dst.probed.unwrap, m.ty), ProbedWays::of(&from.probed.export_sealed, m.ty)]
        .into_iter()
        .flatten()
        .any(|r| r.yes && r.unverified);
    match ProbedWays::of(&dst.probed.unwrap, m.ty) {
        Some(r) if !r.yes => {
            ways.block(format!(
                "{} ({}) does not unwrap a {} ({})",
                dst.token,
                dst.provider,
                describe(m.ty),
                r.said("unwrap.*")
            ));
            return;
        }
        None if !dst.unwraps => {
            ways.block(format!("{} ({}) unwraps nothing", dst.token, dst.provider));
            return;
        }
        _ => {}
    }
    if let Some(r) = ProbedWays::of(&from.probed.export_sealed, m.ty).filter(|r| !r.yes) {
        ways.block(format!(
            "{} ({}) wraps no {} toward another token ({})",
            from.token,
            from.provider,
            describe(m.ty),
            r.said("export.sealed.*")
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
                 `{}`",
                from.token,
                trust_command(None, &from.token)
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
    // For an enforced key, the transport key is the only trusted key, so `CKM_RSA_AES_KEY_WRAP`
    // performs both wraps under it. Its output has the same form as the output of the composed
    // method, so the target unwraps it in the same way. A side that has no RFC 5649 key wrap of
    // its own uses the same mechanism instead (see the module `sealed`).
    let rsa_aes = |s: &Side| cfg!(feature = "kwp") && s.has("CKM_RSA_AES_KEY_WRAP");
    let unwraps_composed = dst.kwp() || rsa_aes(dst);
    let composed = if trusted_only {
        rsa_aes(from) && unwraps_composed
    } else {
        ((from.kwp() && from.has("CKM_AES_KEY_GEN")) || rsa_aes(from)) && unwraps_composed
    };
    if composed {
        ways.offer_unless(Method::RsaOaepAesKwp(hash), exposure, unverified);
    } else if m.ty.class == ObjectClass::SecretKey && m.ty.value_len.is_some_and(|n| n <= OAEP_DIRECT_MAX) {
        ways.offer_unless(Method::RsaOaep(hash), exposure, unverified);
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

/// The largest secret key, in bytes, that RSA-OAEP with SHA-256 carries directly under a 2048-bit
/// transport key (256 - 2 × 32 - 2 bytes). Larger transport keys carry more, and no transport key
/// is smaller (`sealed::check_transport_size`).
const OAEP_DIRECT_MAX: u64 = 190;

/// Returns whether the source can hand the material to the host. The source wraps the material
/// under a session key that cakeys knows, and cakeys unwraps it in memory. Every class uses RFC
/// 5649, which is the one wrap that `Token::extract` undoes; RFC 3394 alone (`CKM_AES_KEY_WRAP`)
/// is not used. A probed `export.host.*` row for the type decides when there is one.
fn host_extractable(from: &Side, ty: &ObjectCfg) -> bool {
    ProbedWays::of(&from.probed.export_host, ty).map_or_else(|| from.kwp(), |r| r.yes)
}

/// Offers the `host` methods into a token, or records why they cannot move the object. A probed
/// `import.*` row for the type decides, and its `via` names the path. Without such a row, the
/// module's claimed path is used.
fn host(m: &Material, from: &Side, dst: &Side, ways: &mut Ways) {
    let ty = m.ty;
    let probed = ProbedWays::of(&dst.probed.import, ty);
    if let Some(r) = probed.filter(|r| !r.yes) {
        ways.block(format!(
            "{} ({}) does not import a {} ({})",
            dst.token,
            dst.provider,
            describe(ty),
            r.said("import.*")
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
    // A yes that only the module reported (for example, a secret key checked by its own
    // commitment) is accepted, and the capability is deferred to the run (review 2026-11-24 E-3).
    let unverified =
        [probed, ProbedWays::of(&from.probed.export_host, ty)].into_iter().flatten().any(|r| r.yes && r.unverified);
    ways.offer_unless(method, Exposure::Host, unverified);
}

/// Returns notes on what the target changes about the object, whichever method moves it.
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

/// Returns the command that a source's SO runs to trust the target's transport key
/// (docs/CAMIGRATE.md D2). A refusal for a missing trusted copy names this command. `object` is
/// the transport key's object, when it is known.
pub(crate) fn trust_command(object: Option<&str>, source: &str) -> String {
    let object = object.map(|o| format!(" {o}")).unwrap_or_default();
    format!("camigrate transport{object} --token <target> --trust-on {source}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::side::Accept;
    use cakeys_core::types::KeyType;

    fn obj(class: ObjectClass, kt: Option<KeyType>) -> ObjectCfg {
        ObjectCfg::new(class, kt)
    }

    /// Parses the command line that a refusal tells its reader to run, as camigrate parses its own
    /// command line. The command is the first span in backticks, with the angle brackets of its
    /// `<placeholders>` removed. A refusal must never name a verb or a flag that the tool does not
    /// have; the renames of 2026-11-23 left `--trusted` in two refusals.
    fn suggested(reason: &str) -> clap::ArgMatches {
        let line = reason.split('`').nth(1).unwrap_or_else(|| panic!("no command in {reason:?}"));
        let mut words: Vec<&str> = line.split_whitespace().map(|w| w.trim_matches(['<', '>'])).collect();
        assert_eq!(words.first(), Some(&"camigrate"), "{line}");
        words.splice(1..1, ["--config", "keys.toml"]);
        crate::command().try_get_matches_from(&words).unwrap_or_else(|e| panic!("{line}: {e}"))
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

    /// AWS `CloudHSM` after its profile subtracts the AES key wraps that it lists but refuses
    /// \[run\]. It has RFC 5649 only inside `CKM_RSA_AES_KEY_WRAP`.
    fn cloudhsm() -> Side {
        let mech = ["CKM_RSA_PKCS_OAEP", "CKM_AES_KEY_GEN", "CKM_RSA_AES_KEY_WRAP"];
        Side::pkcs11("cloudhsm", "aws-cloudhsm", mech.map(String::from))
    }

    /// Returns the plan of an object whose source realisation records `flags`. When `flags` does
    /// not name `CKA_WRAP_WITH_TRUSTED`, the realisation also records it as false, as every
    /// reference module records it. [`plan_exact`] records only `flags`.
    fn plan_of(ty: &ObjectCfg, flags: &[(&str, bool)], from: &Side, to: &To, allow: Allow) -> Plan {
        let mut flags = flags.to_vec();
        if !flags.iter().any(|(n, _)| *n == "CKA_WRAP_WITH_TRUSTED") {
            flags.push(("CKA_WRAP_WITH_TRUSTED", false));
        }
        plan_exact(ty, &flags, from, to, allow)
    }

    fn plan_exact(ty: &ObjectCfg, flags: &[(&str, bool)], from: &Side, to: &To, allow: Allow) -> Plan {
        let policy = policy(flags);
        let immutables = Immutables::default();
        plan(&Material { object: "k", ty, policy: &policy, immutables: &immutables }, from, to, allow)
    }

    /// Checks that the software references use the composed method with the strongest common
    /// OAEP hash: SHA-1 with `SoftHSM`, which implements no other, and SHA-256 between kryoptic
    /// tokens.
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

    /// Checks that an attribute that the source's lock does not record counts as a restriction
    /// (review 2026-11-24 D-7). A data object whose `CKA_PRIVATE` the lock does not record is never
    /// planned as public, whatever is allowed. A key whose `CKA_WRAP_WITH_TRUSTED` the lock does
    /// not record leaves only under a trusted transport key, and never through the host or into a
    /// file. When each attribute is recorded as false, the object moves.
    #[test]
    fn unrecorded_restrictions_restrict() {
        let everything = Allow { host_plaintext: true, trusted_transport: false };
        let data = obj(ObjectClass::Data, None);
        for to in [To::Token(&kryoptic()), To::File(FileFormat::Pkcs8)] {
            let p = plan_exact(&data, &[], &softhsm(), &to, everything);
            assert!(!p.ready && p.method != Some(Method::Public), "{p:?}");
            assert!(p.reasons[0].contains("CKA_PRIVATE"), "{p:?}");
        }
        let p = plan_exact(&data, &[("CKA_PRIVATE", false)], &softhsm(), &To::Token(&kryoptic()), everything);
        assert_eq!((p.method.clone(), p.ready), (Some(Method::Public), true), "{p:?}");
        for to in [To::Token(&kryoptic()), To::File(FileFormat::Pkcs8)] {
            let p = plan_exact(&p256(), &[("CKA_EXTRACTABLE", true)], &softhsm(), &to, everything);
            assert!(!p.ready, "{p:?}");
            assert!(p.reasons.iter().all(|r| r.contains("CKA_WRAP_WITH_TRUSTED")), "{p:?}");
        }
        let recorded = [("CKA_EXTRACTABLE", true), ("CKA_WRAP_WITH_TRUSTED", false)];
        let p = plan_exact(&p256(), &recorded, &softhsm(), &To::Token(&kryoptic()), everything);
        assert!(p.ready, "{p:?}");
    }

    #[test]
    fn public_objects_move_as_they_are() {
        let cert = obj(ObjectClass::Certificate, None);
        let p = plan_of(&cert, &[], &softhsm(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!((p.method, p.exposure, p.ready), (Some(Method::Public), Some(Exposure::Public), true));
        // A target like PIV accepts only certificates.
        let piv = Side { public_import: vec![Accept::class(ObjectClass::Certificate)], ..kryoptic() };
        let data = obj(ObjectClass::Data, None);
        assert!(!plan_of(&data, &[], &softhsm(), &To::Token(&piv), Allow::default()).ready);
        let p = plan_of(&data, &[("CKA_PRIVATE", false)], &softhsm(), &To::Token(&kryoptic()), Allow::default());
        assert_eq!((p.method, p.ready), (Some(Method::Public), true));
        // A private data object's value is a secret, so the object gets no method, whatever is
        // allowed.
        let everything = Allow { host_plaintext: true, trusted_transport: true };
        for to in [To::Token(&kryoptic()), To::File(FileFormat::Pkcs8)] {
            let p = plan_of(&data, &[("CKA_PRIVATE", true)], &softhsm(), &to, everything);
            assert!(!p.ready && p.method.is_none(), "{p:?}");
            assert!(p.reasons[0].contains("private data object"), "{p:?}");
        }
    }

    /// Checks the plans from p11-kit, which has no AES key wrap. A small secret key moves directly
    /// under OAEP. A private key has no sealed path, and the host path also needs an AES key wrap on
    /// the source.
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

    /// Checks a target that imports only plaintext. The plan names the host path even without the
    /// flag, and it refuses a type that the target cannot take.
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
        // Such a token also never exports.
        let p = plan_of(&p256(), &ext, &piv, &To::Token(&kryoptic()), allowed);
        assert!(p.reasons[0].contains("never lets a key leave"), "{p:?}");
    }

    /// Checks what `enforced` needs (docs/CAMIGRATE.md D2). The source must be able to trust a
    /// transport key and must hold a trusted copy of it. A key that OAEP cannot carry alone needs
    /// `CKM_RSA_AES_KEY_WRAP`, which only the patched cryptoki names (the `kwp` feature). An
    /// enforced key never takes a host path and never goes into a file.
    #[test]
    fn wrap_with_trusted_needs_a_trusted_transport_and_never_goes_through_the_host() {
        let flags = [("CKA_EXTRACTABLE", true), ("CKA_WRAP_WITH_TRUSTED", true)];
        let allowed = Allow { host_plaintext: true, ..Allow::default() };
        let p = plan_of(&p256(), &flags, &softhsm(), &To::Token(&kryoptic()), allowed);
        assert!(!p.ready && p.method.is_none(), "{p:?}");
        let why = p.reasons.iter().find(|r| r.contains("holds no trusted copy")).unwrap_or_else(|| panic!("{p:?}"));
        let named = suggested(why);
        let (verb, args) = named.subcommand().unwrap_or_else(|| panic!("{why}"));
        assert_eq!(
            (verb, args.get_one::<String>("trust_on").map(String::as_str)),
            ("transport", Some("softhsm")),
            "{why}"
        );
        // The export's own refusal (sealed.rs) names the transport key's object as well.
        let named = suggested(&format!("`{}`", trust_command(Some("tk"), "softhsm")));
        assert_eq!(named.subcommand().map(|(_, a)| a.get_one::<String>("object").cloned()), Some(Some("tk".into())));
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
        // An AES key fits under OAEP alone. It moves by `CKM_RSA_AES_KEY_WRAP` when this build
        // names that mechanism, and directly under OAEP otherwise.
        let method =
            if cfg!(feature = "kwp") { Method::RsaOaepAesKwp(OaepHash::Sha1) } else { Method::RsaOaep(OaepHash::Sha1) };
        assert_eq!((p.method, p.exposure, p.ready), (Some(method), Some(Exposure::Enforced), true));
        assert!(!plan_of(&p256(), &flags, &softhsm(), &To::File(FileFormat::Pkcs8), trusted).ready);
        // A source that cannot trust an RSA key (kryoptic) never moves the key, whatever is
        // trusted.
        let p = plan_of(&p256(), &flags, &kryoptic(), &To::Token(&softhsm()), trusted);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("move.trusted-wrap row says no")), "{p:?}");
    }

    /// Checks that a side whose only RFC 5649 is inside `CKM_RSA_AES_KEY_WRAP` (`CloudHSM`) uses the
    /// composed method through that mechanism, as a source and as a target, when this build names
    /// the mechanism (the `kwp` feature). Without the feature, a source with an RFC 5649 key wrap of
    /// its own still reaches the host path, which needs its flag. A source without one has no way
    /// to move the key, and the plan says why.
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

    /// Checks that a move to a target whose profile refuses a key kind (`migration.refuses`, such
    /// as `CloudHSM`'s Ed25519 \[run\]) is blocked with that reason, whatever wrap both sides share.
    /// Other keys still move.
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
        // As a source, the same token still exports that key kind.
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

    /// Checks that each fact that the planner names decides on its own, which closes gaps that the
    /// mutation report found. A secret key needs a target that reports its length. The composed
    /// method needs RFC 5649 on both sides and a KEK that the source can make; without the
    /// composed method, only a small secret key moves directly. The host path creates a private key
    /// from PKCS#8 and a secret key from its value, and a tool import takes only what it lists. A
    /// file carries only private keys. Refusals name the object's type.
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
        // A target that reports no length for an unwrapped secret key takes only private keys.
        let lengthless = Side { secret_unwraps: false, plaintext_import: None, ..both.clone() };
        assert_eq!(sealed_to(&p256(), &both, &lengthless).method, composed);
        let p = sealed_to(&aes, &both, &lengthless);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("without its length")), "{p:?}");
        // The composed method needs RFC 5649 on the source and on the target, and a KEK that the
        // source can generate.
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
            // A small secret key moves directly under OAEP, but a large one never does.
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
        // A file in either format carries only private keys.
        for format in [FileFormat::Pkcs8, FileFormat::Pkcs12] {
            let p = plan_of(&aes, &ext, &both, &To::File(format), allowed);
            assert!(!p.ready && p.reasons.iter().any(|r| r.contains("carry private keys")), "{p:?}");
        }
    }

    /// Checks that `enforced` needs both `CKM_RSA_AES_KEY_WRAP` on the source and RFC 5649 on the
    /// target. Without either one, a private key cannot leave under the trusted transport key.
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

    /// Checks that the plan of a key on the host path says why no sealed way would carry it,
    /// because the fix may be a profile or a mechanism instead of --allow-host-plaintext (review
    /// plan.rs F2).
    #[test]
    fn a_host_plan_says_why_it_is_not_sealed() {
        let ext = [("CKA_EXTRACTABLE", true)];
        // A target that unwraps nothing leaves only the host path, through its create-object
        // import.
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

    /// Checks that a probed row decides for the type that it covers, before the module's claims
    /// (`docs/archive/CAPROBE_MIGRATION.md`, M4), and only for that type.
    #[test]
    fn probed_rows_decide_before_the_claims_for_their_type() {
        use crate::side::{Probed, ProbedWays};
        let ext = [("CKA_EXTRACTABLE", true)];
        let p256_rows = |yes, via: Option<&str>| {
            vec![Probed {
                covers: Accept { curves: vec!["secp256r1"], ..Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec]) },
                yes,
                via: via.map(str::to_owned),
                unknown: None,
                unverified: false,
            }]
        };
        let host = Allow { host_plaintext: true, ..Allow::default() };
        // The target claims `C_CreateObject`, but its import row for P-256 says no, so there is no
        // host path for P-256. A P-384 key, which no row covers, still follows the claim.
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
        // The target claims to unwrap nothing, but its unwrap row for P-256 says yes, so the move
        // is sealed.
        let unwraps = Side {
            unwraps: false,
            probed: ProbedWays { unwrap: p256_rows(true, Some("rsa-oaep-sha1+aes-kwp")), ..ProbedWays::default() },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&unwraps), Allow::default());
        assert_eq!((p.exposure, p.ready), (Some(Exposure::Sealed), true), "{:?}", p.reasons);
        // An import row's path decides the method, even for a module whose claim is `tpm2_ptool`
        // for no type at all.
        let ptool = Side {
            unwraps: false,
            plaintext_import: Some(PlaintextImport::Tpm2Ptool(vec![])),
            probed: ProbedWays { import: p256_rows(true, Some("tpm2-ptool")), ..ProbedWays::default() },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &softhsm(), &To::Token(&ptool), host);
        assert_eq!(p.method, Some(Method::Tpm2Ptool), "{:?}", p.reasons);
        // The source claims to export, but both of its export rows for P-256 say no, so the key
        // stays.
        let keeps = Side {
            probed: ProbedWays {
                export_host: p256_rows(false, None),
                export_sealed: p256_rows(false, None),
                ..ProbedWays::default()
            },
            ..softhsm()
        };
        let p = plan_of(&p256(), &ext, &keeps, &To::Token(&kryoptic()), host);
        assert!(
            !p.ready
                && p.reasons
                    .iter()
                    .any(|r| r.contains("its export.host.* row says no; its export.sealed.* row says no")),
            "{p:?}"
        );
        // For a public object, the create row decides before the claimed classes.
        let cert = obj(ObjectClass::Certificate, None);
        let no_certs = Side {
            probed: ProbedWays {
                create: vec![Probed {
                    covers: Accept::class(ObjectClass::Certificate),
                    yes: false,
                    via: None,
                    unknown: None,
                    unverified: false,
                }],
                ..ProbedWays::default()
            },
            ..softhsm()
        };
        let p = plan_of(&cert, &[], &softhsm(), &To::Token(&no_certs), host);
        assert!(!p.ready && p.reasons.iter().any(|r| r.contains("its create.* row says no")), "{p:?}");
    }

    /// Checks that a way that depends on a probed yes that only the module reported
    /// (`by = "unverified"`) plans as ready and defers the capability to the run. This applies to
    /// the sealed export of the source, the unwrap of the target, and the target's import on the
    /// host path. A yes that the host checked defers nothing (review 2026-11-24 E-3, P2's
    /// leftover).
    #[test]
    fn an_unverified_probed_yes_defers_the_capability() {
        use crate::side::{Probed, ProbedWays};
        let ext = [("CKA_EXTRACTABLE", true)];
        let rows = |unverified| {
            vec![Probed {
                covers: Accept { curves: vec!["secp256r1"], ..Accept::key(ObjectClass::PrivateKey, &[KeyType::Ec]) },
                yes: true,
                via: Some("rsa-oaep-sha256+aes-kwp".into()),
                unknown: None,
                unverified,
            }]
        };
        let capability = Rule::Capability.name();
        for unverified in [false, true] {
            let to = Side { probed: ProbedWays { unwrap: rows(unverified), ..ProbedWays::default() }, ..kryoptic() };
            let from =
                Side { probed: ProbedWays { export_sealed: rows(unverified), ..ProbedWays::default() }, ..kryoptic() };
            for (from, to) in [(&kryoptic(), &to), (&from, &kryoptic())] {
                let p = plan_of(&p256(), &ext, from, &To::Token(to), Allow::default());
                assert_eq!((p.exposure, p.ready), (Some(Exposure::Sealed), true), "{p:?}");
                assert_eq!(p.deferred.contains(&capability), unverified, "{p:?}");
            }
            let to = Side {
                unwraps: false,
                probed: ProbedWays { import: rows(unverified), ..ProbedWays::default() },
                ..kryoptic()
            };
            let host = Allow { host_plaintext: true, ..Allow::default() };
            let p = plan_of(&p256(), &ext, &kryoptic(), &To::Token(&to), host);
            assert_eq!((p.exposure, p.ready), (Some(Exposure::Host), true), "{p:?}");
            assert_eq!(p.deferred.contains(&capability), unverified, "{p:?}");
        }
    }
}
