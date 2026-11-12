//! Idempotent verbs with HTTP-like semantics (PLAN.md, "Token verbs").

use crate::token::{self as hal, Token};
use cakeys_core::config::{
    AttestationRecord, AttrValue, Binding, Immutables, Lock, LockRealisation, Mode, Observed, Provenance,
};
use cakeys_core::id::{self, Commit, HmacHash, Scheme};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{KeyType, ObjectHandle};
use serde::Serialize;
use std::collections::BTreeMap;

pub use cakeys_core::plan::{Target, binding, plan_mode};
use cakeys_core::plan::{AES_COMMITS, declared_commits};

/// The attestation scheme `t`'s token computes when opted in (`attestation = true`), if the
/// provider attests this class at all (§3.7 of docs/DESIGN.md).
fn attestation_scheme(t: &Target, tok: &Token) -> Option<Scheme> {
    t.on_token.attestation.then(|| tok.attestation_cap(t.object)).flatten().map(|c| c.scheme)
}

/// Commitments to compute for a secret key on this token: those the spec allows (or, for a
/// wrap-rebind copy, every one for the key type) that the token implements.
fn commits(t: &Target, tok: &Token, mode: Mode) -> Result<Vec<Commit>> {
    let wanted = match (mode, t.object.key_type) {
        (Mode::Commitment, _) => declared_commits(t),
        (Mode::WrapRebind, Some(Kt::Aes)) => AES_COMMITS.to_vec(),
        (Mode::WrapRebind, kt) => kt.and_then(HmacHash::for_key_type).map(Commit::Hmac).into_iter().collect(),
        _ => return Ok(vec![]),
    };
    let usable: Vec<Commit> = wanted.iter().copied().filter(|c| tok.has(hal::commit_mechanism(*c))).collect();
    if usable.is_empty() {
        let mechs: Vec<String> = wanted.iter().map(|c| hal::commit_mechanism(*c).to_string()).collect();
        return Err(tok.unsupported(format!(
            "token '{}' implements none of {} needed for mode '{mode}' of {}",
            tok.name,
            mechs.join(", "),
            t
        )));
    }
    Ok(usable)
}

/// Schemes this spec computes on this token: `Target::schemes` narrowed to the commitments the
/// token implements, plus the attestation scheme when the spec opted in and the provider
/// attests the class (§3.7). Needs no object, so callers can refuse before anything is created.
pub fn schemes_on(t: &Target, tok: &Token) -> Result<Vec<Scheme>> {
    let mut v = if t.object.class != Class::SecretKey {
        t.schemes()
    } else {
        commits(t, tok, plan_mode(t)?)?.iter().map(|c| c.scheme()).collect()
    };
    if let Some(s) = attestation_scheme(t, tok) {
        v.push(s);
    }
    Ok(v)
}

/// Token capabilities the mode needs, checked before anything is created.
fn check_capabilities(t: &Target, tok: &Token, mode: Mode) -> Result<()> {
    if mode.needs_opt_in() {
        return Err(KmError::Unsupported(format!(
            "identity mode '{mode}' (opted in for {}) is not implemented in this POC",
            t
        )));
    }
    // An attestation the provider cannot compute is refused up front (15), like a scheme the
    // token lacks: it is part of the identity this realisation promises from now on.
    if t.on_token.attestation {
        match tok.provider.attestation() {
            None => {
                return Err(tok.unsupported(format!(
                    "{} opts into attestation, but provider '{}' attests nothing on this module",
                    t,
                    tok.provider.name()
                )))
            }
            Some(cap) if !cap.classes.contains(&t.object.class) => {
                return Err(tok.unsupported(format!(
                    "{} opts into attestation, but provider '{}' attests only {:?}",
                    t,
                    tok.provider.name(),
                    cap.classes.iter().map(|c| c.name()).collect::<Vec<_>>()
                )))
            }
            Some(_) => {}
        }
    }
    let mut need = Vec::new();
    if t.on_token.auto_create && let Some(kt) = t.object.key_type.filter(|k| k.is_hash_bound_hmac()) {
        // CKM_GENERIC_SECRET_KEY_GEN makes CKK_GENERIC_SECRET keys; there is no mechanism for
        // the hash-bound HMAC types (SoftHSM: CKR_TEMPLATE_INCONSISTENT).
        return Err(tok.unsupported(format!(
            "{}: PKCS#11 has no key generation for {}; generate a CKK_GENERIC_SECRET with CKA_SIGN, \
             or create the key elsewhere and adopt it",
            t,
            kt
        )));
    }
    if t.on_token.auto_create {
        need.push(match hal::key_type_of(t.object)? {
            KeyType::EC => MechanismType::ECC_KEY_PAIR_GEN,
            KeyType::EC_EDWARDS => MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
            KeyType::RSA => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            KeyType::AES => MechanismType::AES_KEY_GEN,
            _ => MechanismType::GENERIC_SECRET_KEY_GEN,
        });
    }
    commits(t, tok, mode)?;
    if mode == Mode::WrapRebind {
        need.push(MechanismType::AES_KEY_GEN);
        if !tok.has(MechanismType::AES_KEY_WRAP_PAD) {
            need.push(MechanismType::AES_KEY_WRAP);
        }
    }
    match need.into_iter().find(|m| !tok.has(*m)) {
        Some(m) => Err(tok.unsupported(format!(
            "token '{}' lacks {m} needed for mode '{mode}' of {}",
            tok.name,
            t
        ))),
        None => Ok(()),
    }
}

#[derive(Debug, Serialize)]
pub struct Resolved {
    pub object: String,
    pub spec: String,
    pub token: String,
    pub uri: String,
    pub mode: Mode,
    #[serde(rename = "publicOnly")]
    pub public_only: bool,
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
    pub ids: BTreeMap<String, String>,
    /// Private keys: how the private object was bound to `ids` (proven when `pop-sign`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// The observed policy vector and immutables of the object found (§4.2 of docs/DESIGN.md).
    pub policy: BTreeMap<String, AttrValue>,
    #[serde(skip_serializing_if = "Immutables::is_empty")]
    pub immutables: Immutables,
    /// Label the commitment schemes in `ids` were computed with (none for public-material IDs).
    #[serde(rename = "commitmentLabel", skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// The attestation this realisation computed (§3.7), when its spec opted in: `kind` names
    /// the evidence, `root` the anchor it verified to, `id` the per-device attestation ID. Never
    /// in `ids`, which holds only the portable schemes shared across tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRecord>,
}

/// The label to compute `t`'s commitments with: the one the lock records for the object, else the
/// default for objects the lock does not know yet.
fn commitment_label(t: &Target, lock: &Lock) -> String {
    lock.objects
        .get(t.object_name)
        .and_then(|o| o.commitment_label.clone())
        .unwrap_or_else(|| id::DEFAULT_COMMITMENT_LABEL.to_owned())
}

/// GET: find by locator (exactly one), check type and attributes, compute IDs. Never writes,
/// neither the lock nor the token: a TPM Attestation Key that is not provisioned yet is an
/// error here, and only `realise` provisions it.
pub fn resolve(t: &Target, tok: &Token, lock: &Lock) -> Result<Option<Resolved>> {
    resolve_with(t, tok, lock, false)
}

fn resolve_with(t: &Target, tok: &Token, lock: &Lock, provision: bool) -> Result<Option<Resolved>> {
    let mode = plan_mode(t)?;
    let public_only = t.on_token.public_only;
    let Some(h) = tok.find_key(t.object, &t.on_token.locator, public_only)? else {
        return Ok(None);
    };
    tok.check(h, t.object, t.spec)?;
    if t.object.class.is_asymmetric() || t.object.class == Class::Certificate {
        tok.check_unique_private_id(h)?;
    }
    tok.check_public_half(h, t.spec, &t.on_token.locator, public_only)?;
    let commits = commits(t, tok, mode)?;
    let label = commitment_label(t, lock);
    let binding = binding(t);
    let ids = tok.ids(h, t.object, &t.on_token.locator, mode, &commits, &label, binding)?;
    let attestation = match attestation_scheme(t, tok) {
        Some(scheme) => Some(attest(t, tok, lock, h, scheme, provision)?),
        None => None,
    };
    Ok(Some(Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: tok.uri(t.object, &t.on_token.locator)?,
        mode,
        public_only,
        spec_digest: id::spec_digest(t.object, t.spec),
        ids,
        binding,
        policy: tok.policy(h)?,
        immutables: tok.immutables(h),
        commitment_label: (!commits.is_empty()).then_some(label),
        attestation,
    }))
}

/// The attestation commitment (§3.7): per-device identity from signed provenance. The material
/// SPKI it must name comes from the same source `rfc7093m4` hashed, so an attestation of other
/// material is a conflict, not a second opinion.
///
/// Once the lock pins an attestation for this realisation, a run that cannot attest — the TPM
/// unreachable, no PIN, no attestation certificate — is a scheme downgrade (14), like any
/// scheme a realisation stops computing. Conflicts (13) and ambiguity (12) keep their codes:
/// they say the evidence is wrong, not absent.
fn attest(t: &Target, tok: &Token, lock: &Lock, h: ObjectHandle, scheme: Scheme, provision: bool) -> Result<AttestationRecord> {
    let asymmetric = t.object.class.is_asymmetric();
    let spki = if asymmetric { Some(tok.spki(h, &t.on_token.locator)?) } else { None };
    let kind = scheme
        .attestation_kind()
        .ok_or_else(|| KmError::Unsupported(format!("provider '{}' advertises unknown attestation scheme {scheme}", tok.provider.name())))?;
    let a = match tok.attest(h, t.object, spki.as_deref(), provision) {
        Ok(a) => a,
        Err(e @ (KmError::Unavailable(_) | KmError::Unsupported(_) | KmError::NotFound(_))) => {
            let locked = lock.realisation(t.spec_name, t.token_name).and_then(|r| r.attestation.as_ref());
            return Err(match locked {
                Some(was) => KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it cannot compute now: {e}",
                    t,
                    was.kind
                )),
                None => e,
            });
        }
        Err(e) => return Err(e),
    };
    if a.scheme != scheme {
        return Err(KmError::Conflict(format!(
            "provider '{}' advertises {scheme} but attested {}",
            tok.provider.name(),
            a.scheme
        )));
    }
    Ok(AttestationRecord { kind: kind.to_owned(), root: a.root, id: a.id })
}

/// Compare computed IDs with the lock; optionally record them (only ever fills gaps).
fn reconcile(t: &Target, tok: &Token, r: &Resolved, lock: &mut Lock, update: bool) -> Result<bool> {
    // The lock pins the type its IDs were computed for: a different type is different material,
    // so say so instead of reporting a hash mismatch (also when updating).
    if let Some(locked) = lock.objects.get(t.object_name).and_then(|o| o.object_type.as_ref()) && locked != t.object {
        return Err(KmError::PreconditionFailed(format!(
            "the type of object '{}' in keys.toml changed since it was locked: locked {}, now {}; \
             different material needs a new object name",
            t.object_name,
            locked,
            t.object
        )));
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        // Like a lockfile out of date: keys.toml changed what this realisation is (another
        // object, locator, publicOnly or policy), so the lock must be re-recorded after review.
        if !update {
            let mut diff = Vec::new();
            if prev.object != t.object_name {
                diff.push(format!("object '{}' -> '{}'", prev.object, t.object_name));
            }
            if prev.locator != t.on_token.locator {
                diff.push(format!("locator {} -> {}", prev.locator, t.on_token.locator));
            }
            if prev.public_only != r.public_only {
                diff.push(format!("publicOnly {} -> {}", prev.public_only, r.public_only));
            }
            if prev.spec_digest != r.spec_digest {
                diff.push(format!("spec digest {} -> {}", prev.spec_digest, r.spec_digest));
            }
            if !diff.is_empty() {
                return Err(KmError::PreconditionFailed(format!(
                    "spec '{}' changed in keys.toml since it was realised on '{}' ({}); \
                     review the change, then `realise`",
                    t.spec_name,
                    t.token_name,
                    diff.join(", ")
                )));
            }
        }
        if r.mode > prev.mode {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: locked mode '{}', now only '{}'",
                t, prev.mode, r.mode
            )));
        }
        if let (Some(was), Some(now)) = (prev.binding, r.binding) && now.rank() > was.rank() {
            return Err(KmError::PreconditionFailed(format!(
                "binding downgrade for {}: locked binding '{was}', now only '{now}'",
                t
            )));
        }
        // The attestation is compared, even when realise writes the lock (§3.7). A different anchor means
        // a different device (or a re-provisioned TPM) signed the provenance; a different ID
        // under the same anchor means the attested object changed (re-imported, other
        // attributes or policy). Both are changes to review, never to re-record — and a lost
        // attestation is a scheme downgrade.
        match (&prev.attestation, &r.attestation) {
            (Some(was), Some(now)) if was.kind != now.kind || was.root != now.root => {
                return Err(KmError::PreconditionFailed(format!(
                    "attestation anchor for {} changed since it was realised ({} root {}, now {} root {}); \
                     the material needs a new object name",
                    t,
                    was.kind,
                    was.root,
                    now.kind,
                    now.root
                )));
            }
            (Some(was), Some(now)) if was.id != now.id => {
                return Err(KmError::HashMismatch {
                    what: format!("{} ({} attestation)", t, was.kind),
                    expected: was.id.clone(),
                    got: now.id.clone(),
                });
            }
            (Some(was), None) => {
                return Err(KmError::PreconditionFailed(format!(
                    "identity downgrade for {}: it was realised with a {} attestation, which it no longer computes",
                    t,
                    was.kind
                )));
            }
            (None, Some(now)) if !update => {
                eprintln!(
                    "note: {} also has a {} attestation the lock does not record; `realise` adds it",
                    t,
                    now.kind
                );
            }
            _ => {}
        }
        let lost: Vec<&String> = prev.schemes.iter().filter(|s| !r.ids.contains_key(*s)).collect();
        if !lost.is_empty() {
            return Err(KmError::PreconditionFailed(format!(
                "identity downgrade for {}: it was realised with {lost:?}, which it no longer computes",
                t
            )));
        }
        // Fixed at creation: weaker now means the object was replaced (also when updating).
        let weakened = r.immutables.weakened_since(&prev.immutables);
        if !weakened.is_empty() {
            return Err(KmError::PreconditionFailed(format!(
                "{} was replaced since it was realised: {} no longer true; a new object needs a new name",
                t,
                weakened.join(", ")
            )));
        }
        // The token's object changed (policy set since, or another object with the same
        // material): review, like a changed spec.
        if !update {
            let mut diff: Vec<String> = prev
                .policy
                .iter()
                .filter(|(n, was)| r.policy.get(*n) != Some(was))
                .map(|(n, was)| format!("{n} {was} -> {}", r.policy.get(n).map_or("unreadable".into(), |b| b.to_string())))
                .collect();
            if prev.immutables != r.immutables {
                diff.push(format!(
                    "immutables {} -> {}",
                    prev.immutables,
                    r.immutables
                ));
            }
            if !diff.is_empty() {
                return Err(KmError::PreconditionFailed(format!(
                    "{} changed on the token since it was realised ({}); review, then `realise`",
                    t,
                    diff.join(", ")
                )));
            }
            let new: Vec<&String> = r.policy.keys().filter(|n| !prev.policy.contains_key(*n)).collect();
            if !new.is_empty() {
                eprintln!(
                    "note: {} also reports {new:?}, which the lock does not record; `realise` adds them",
                    t
                );
            }
        }
    }
    if let Some(prev) = lock.realisation(t.spec_name, t.token_name) {
        warn_provenance(t, tok, prev);
    }
    let unlisted = lock.unlisted_pairs(t.object_name);
    if !update && !unlisted.is_empty() {
        eprintln!(
            "note: {unlisted:?} share the public key of '{}' but are not listed as its pairs; `realise` records them",
            t.object_name
        );
    }
    let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
    // A deprecated computation still verifies — its identities are pinned — but the lock should
    // move to the replacement (docs/DESIGN.md §3.1); a lock write never adds a new one.
    for scheme in locked.iter().flat_map(|ids| ids.keys()).filter(|s| Scheme::from_name(s).is_some_and(Scheme::is_deprecated)) {
        eprintln!(
            "warning: the {scheme} identity of '{}' uses a deprecated computation; migrate to its replacement (docs/DESIGN.md §3.1)",
            t.object_name
        );
    }
    // Material is only linked through a shared scheme: never attach IDs to an object when none of
    // them can be compared with what is already locked (e.g. a CMAC-only and a KW-only spec).
    if let Some(ids) = locked.filter(|ids| !ids.is_empty()) && !r.ids.keys().any(|s| ids.contains_key(s)) {
        return Err(KmError::PreconditionFailed(format!(
            "{} computes {:?} but '{}' is locked only by {:?}: nothing shows it is the same \
             material; realise a spec that computes both first",
            t,
            r.ids.keys().collect::<Vec<_>>(),
            t.object_name,
            ids.keys().collect::<Vec<_>>()
        )));
    }
    let mut changed = false;
    let mut matched = false;
    let mut unlocked = Vec::new();
    for (scheme, got) in &r.ids {
        match locked.and_then(|ids| ids.get(scheme)) {
            Some(want) if want == got => matched = true,
            Some(want) => {
                return Err(KmError::HashMismatch { what: t.to_string(), expected: want.clone(), got: got.clone() })
            }
            None if update && Scheme::from_name(scheme).is_some_and(Scheme::is_deprecated) => {}
            None if update => changed = true,
            None => unlocked.push((scheme, got)),
        }
    }
    // A scheme not yet in the lock (e.g. one a newer cakeys computes) is fine once another
    // scheme proved the identity; with nothing to compare it is first use and fails like a FOD.
    if let Some((_, got)) = unlocked.first().filter(|_| !matched) {
        return Err(KmError::HashMismatch { what: t.to_string(), expected: "<none>".into(), got: (*got).clone() });
    }
    // The material matches, but the lock does not say this spec is realised on this token: the
    // lock describes where objects live, not only what they are.
    if !update && lock.realisation(t.spec_name, t.token_name).is_none() {
        return Err(KmError::PreconditionFailed(format!(
            "{} matches the locked identity, but the lock records no realisation of spec '{}' on \
             token '{}'; review, then `realise`",
            t,
            t.spec_name,
            t.token_name
        )));
    }
    for (scheme, _) in &unlocked {
        eprintln!(
            "note: {} also has a {scheme} identity the lock does not record; `realise` adds it",
            t
        );
    }
    // Locked schemes not checked now: unknown to this cakeys (e.g. from a newer one), or not
    // computable for this spec on this token.
    for scheme in locked.into_iter().flat_map(|ids| ids.keys()).filter(|s| !r.ids.contains_key(*s)) {
        if Scheme::from_name(scheme).is_some() {
            eprintln!("note: {} is not checked by its {scheme} identity here (not computable for this spec on this token)", t);
        } else {
            eprintln!("warning: the lock records a {scheme} identity for '{}' that this cakeys does not know; it is not checked", t.object_name);
        }
    }
    if update {
        // One object per material (checked again on load): refuse to record the same material
        // under a second name.
        let class = t.object.class;
        for (name, o) in lock.objects.iter().filter(|(n, o)| *n != t.object_name && o.object_type.as_ref().is_some_and(|ty| ty.class == class)) {
            if let Some((s, _)) = r.ids.iter().find(|(s, v)| !(class == Class::Certificate && *s == Scheme::Rfc7093m4.name()) && o.ids.get(*s) == Some(v)) {
                return Err(KmError::PreconditionFailed(format!(
                    "{} is the same material as object '{name}' ({s}); use that object instead of a second name",
                    t
                )));
            }
        }
        let entry = lock.objects.entry(t.object_name.into()).or_default();
        if entry.object_type.is_none() {
            entry.object_type = Some(t.object.clone());
            changed = true;
        }
        if let Some(label) = &r.commitment_label && entry.commitment_label.as_ref().is_none_or(|l| l != label) {
            entry.commitment_label = Some(label.clone());
            changed = true;
        }
        for (scheme, got) in &r.ids {
            if Scheme::from_name(scheme).is_some_and(Scheme::is_deprecated) && !entry.ids.contains_key(scheme) {
                eprintln!(
                    "note: {} also computes a {scheme} identity; not recorded: that computation is deprecated (docs/DESIGN.md §3.1)",
                    t
                );
                continue;
            }
            entry.ids.entry(scheme.clone()).or_insert_with(|| got.clone());
        }
        let real = LockRealisation {
            object: t.object_name.to_owned(),
            locator: t.on_token.locator.clone(),
            spec_digest: r.spec_digest.clone(),
            mode: r.mode,
            schemes: r.ids.keys().cloned().collect(),
            public_only: r.public_only,
            binding: r.binding,
            attestation: r.attestation.clone(),
            policy: r.policy.clone(),
            immutables: r.immutables.clone(),
            observed: Some(Observed {
                uri: r.uri.clone(),
                session: if tok.logged_in { "user" } else { "public" }.to_owned(),
                mechanisms: tok.mechanism_names().to_vec(),
            }),
            provenance: Some(Provenance {
                provider: tok.provider.name().to_owned(),
                cakeys_version: env!("CARGO_PKG_VERSION").to_owned(),
                module: tok.module.clone(),
                token: tok.token.clone(),
            }),
        };
        let slot = lock.realisations.entry(t.spec_name.into()).or_default();
        if slot.get(t.token_name) != Some(&real) {
            slot.insert(t.token_name.into(), real);
            changed = true;
        }
        // Partners in this file are recomputed; listed ones from other fragments are kept.
        let pairs = lock.computed_pairs();
        let present: Vec<String> = lock.objects.keys().cloned().collect();
        for (name, o) in lock.objects.iter_mut() {
            let mut want = pairs.get(name).cloned().unwrap_or_default();
            want.extend(o.pairs.iter().filter(|p| !present.contains(p)).cloned());
            if o.pairs != want {
                o.pairs = want;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// `observed` and `provenance` never change a verdict: identity is enforced by the CA-IDs, so a
/// different module build or token only warns. `realise` re-binds them.
fn warn_provenance(t: &Target, tok: &Token, prev: &LockRealisation) {
    if prev.observed.as_ref().is_some_and(|o| o.session == "user") && !tok.logged_in {
        eprintln!(
            "warning: {} was realised in a user session; this public session cannot see other private keys under its CKA_ID",
            t
        );
    }
    if let Some(o) = &prev.observed {
        let gone: Vec<&str> =
            o.mechanisms.iter().filter(|m| !tok.mechanism_names().contains(m)).map(String::as_str).collect();
        if !gone.is_empty() {
            eprintln!(
                "warning: {} was realised where the token offered {}, which it no longer does (functions.<token> in Nix)",
                t,
                gone.join(", ")
            );
        }
    }
    let Some(p) = &prev.provenance else { return };
    if p.provider != tok.provider.name() {
        eprintln!("warning: {} was realised with provider {}, now {}", t, p.provider, tok.provider.name());
    }
    if p.cakeys_version != env!("CARGO_PKG_VERSION") {
        eprintln!("note: {} was realised by cakeys {}, now {}", t, p.cakeys_version, env!("CARGO_PKG_VERSION"));
    }
    let m = &p.module;
    if !m.same_build_identity(&tok.module) {
        eprintln!(
            "warning: {} was realised with module {} {} ({}), now {} {} ({})",
            t,
            m.description,
            m.version,
            m.manufacturer,
            tok.module.description,
            tok.module.version,
            tok.module.manufacturer
        );
    } else if m.path != tok.module.path {
        eprintln!("note: {} was realised with module file {}, now {}", t, m.path, tok.module.path);
    }
    let k = &p.token;
    if k != &tok.token {
        eprintln!(
            "warning: {} was realised on token {} #{} (firmware {}), now {} #{} (firmware {})",
            t,
            k.model,
            k.serial,
            k.firmware,
            tok.token.model,
            tok.token.serial,
            tok.token.firmware
        );
    }
}

/// GET + If-Match against the lock.
pub fn verify(t: &Target, tok: &Token, lock: &Lock) -> Result<Resolved> {
    let r = resolve(t, tok, lock)?.ok_or_else(|| KmError::NotFound(t.to_string()))?;
    reconcile(t, tok, &r, &mut lock.clone(), false)?;
    Ok(r)
}

/// PUT: create under the declared locator if absent (and `autoCreate`), then compare with the lock.
/// Re-running never creates a second object: the locator finds the first one.
pub fn realise(t: &Target, tok: &Token, lock: &mut Lock, update: bool) -> Result<(Resolved, bool)> {
    let mode = plan_mode(t)?;
    check_capabilities(t, tok, mode)?;
    let r = match resolve_with(t, tok, lock, true)? {
        Some(r) => r,
        None if t.on_token.auto_create => {
            // D1: the lock already pins this object's material, so a fresh generation can only
            // end in a mismatch; refuse before anything is created. (Had this token held the
            // same material, resolve above would have found it.)
            if let Some(ids) = lock.objects.get(t.object_name).map(|o| &o.ids).filter(|ids| !ids.is_empty()) {
                return Err(KmError::PreconditionFailed(format!(
                    "{}: the lock already pins object '{}' ({}); autoCreate would generate \
                     different material that can never match; put the same material under the \
                     locator, or give this token's key its own object name",
                    t,
                    t.object_name,
                    ids.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
                )));
            }
            // If-None-Match: never create over anything else under the locator. On a PIV
            // token, generating into an occupied slot would silently replace its key.
            let present = tok.find_any(&t.on_token.locator)?;
            if !present.is_empty() {
                return Err(KmError::Conflict(format!(
                    "{} objects of another class already sit under the locator of {}; refusing to create",
                    present.len(),
                    t
                )));
            }
            tok.create(t.object, t.spec, &t.on_token.locator)?;
            eprintln!("created {}", t);
            match resolve_with(t, tok, lock, true).and_then(|r| {
                r.ok_or_else(|| KmError::NotFound(format!("{} vanished after creation", t)))
            }) {
                Ok(r) => r,
                Err(e) => {
                    // The locator was empty before (If-None-Match), so this removes only what we
                    // just made: a refused realise leaves nothing behind, unless the module cannot
                    // delete keys (ykcs11), which is then said rather than claimed.
                    match tok.destroy(t.object, &t.on_token.locator) {
                        Ok(n) => eprintln!(
                            "removed {n} object(s) just created for {}: its identity could not be established",
                            t
                        ),
                        Err(d) => eprintln!(
                            "the key just created for {} is still on the token (its identity could not be \
                             established, and removing it failed: {d})",
                            t
                        ),
                    }
                    return Err(e);
                }
            }
        }
        None => return Err(KmError::NotFound(format!("{} (autoCreate is off)", t))),
    };
    let changed = reconcile(t, tok, &r, lock, update)?;
    Ok((r, changed))
}

/// DELETE + If-Match. Absent is success; a different object under the locator is left alone.
pub fn delete(t: &Target, tok: &Token, lock: &mut Lock, if_match: Option<&str>, update: bool) -> Result<bool> {
    if t.on_token.public_only {
        return Err(KmError::Unsupported(format!(
            "{} is adopted publicOnly; deleting would remove only the public half",
            t
        )));
    }
    // An expected identity is only required when there is something to delete.
    if let Some(h) = tok.find_key(t.object, &t.on_token.locator, false)? {
        let mode = plan_mode(t)?;
        // Proven like `resolve`: If-Match must not pass on a public object beside another key.
        let got = tok.ids(h, t.object, &t.on_token.locator, mode, &commits(t, tok, mode)?, &commitment_label(t, lock), binding(t))?;
        // --if-match names the primary scheme; otherwise the first scheme the lock records.
        let locked = lock.objects.get(t.object_name).map(|o| &o.ids);
        let primary = t.schemes().into_iter().find(|s| got.contains_key(s.name()));
        let (scheme, expected) = match if_match {
            Some(want) => (primary, Some(want.to_owned())),
            None => t
                .schemes()
                .into_iter()
                .filter(|s| got.contains_key(s.name()))
                .find_map(|s| locked.and_then(|ids| ids.get(s.name())).map(|w| (Some(s), Some(w.clone()))))
                .unwrap_or((primary, None)),
        };
        let scheme = scheme.ok_or_else(|| KmError::Unsupported(format!("no identity computed for {}", t)))?;
        let expected = expected
            .ok_or_else(|| KmError::PreconditionFailed(format!("no expected {scheme} for {}; pass --if-match", t)))?;
        if got.get(scheme.name()) != Some(&expected) {
            return Err(KmError::PreconditionFailed(format!(
                "{} holds {:?}, expected {expected}; not deleting",
                t, got.get(scheme.name())
            )));
        }
    }
    let n = tok.destroy(t.object, &t.on_token.locator)?;
    if n > 0 {
        eprintln!("destroyed {n} object(s) for {}", t);
    }
    let mut changed = false;
    if update && let Some(m) = lock.realisations.get_mut(t.spec_name) {
        changed = m.remove(t.token_name).is_some();
        if m.is_empty() {
            lock.realisations.remove(t.spec_name);
        }
    }
    Ok(changed)
}
